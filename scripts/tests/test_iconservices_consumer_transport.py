"""Static safety checks for the transparent consumer transport split."""

from __future__ import annotations

import unittest
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "Cyanide/installer"
HOOK = INSTALLER / "CNDIconServicesConsumerHook.m"
LIFECYCLE = INSTALLER / "CNDIconServicesConsumerLifecycleCoordinator.m"
BRIDGE = ROOT / "Cyanide/TaskRop/CNDKernelTaskBridge.m"
REMOTE_CALL = ROOT / "Cyanide/TaskRop/RemoteCall.m"
THEMER = ROOT / "Cyanide/tweaks/themer.m"
APP_DELEGATE = ROOT / "Cyanide/AppDelegate.m"
SETTINGS = ROOT / "Cyanide/SettingsViewController.m"
SNOWBOARD_LITE = ROOT / "Cyanide/tweaks/snowboardlite.m"


class IconServicesConsumerTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.hook = HOOK.read_text(encoding="utf-8")
        cls.lifecycle = LIFECYCLE.read_text(encoding="utf-8")
        cls.bridge = BRIDGE.read_text(encoding="utf-8")
        cls.remote_call = REMOTE_CALL.read_text(encoding="utf-8")
        cls.themer = THEMER.read_text(encoding="utf-8")

    def test_arm64e_forged_task_port_fails_closed_before_mutation(self) -> None:
        open_start = self.bridge.index("+ (instancetype)openPID:")
        probe_start = self.bridge.index(
            "NSDictionary<NSString *, id> *\nCNDKernelTaskBridgeProbeProcess"
        )
        open_body = self.bridge[open_start:probe_start]
        guard = open_body.index("if (gIsPACSupported)")
        mutation = open_body.index(
            "kwrite64(portObject + off_ipc_port_ip_kobject, task)"
        )
        self.assertLess(guard, mutation)
        self.assertIn("destination-specific kernel PAC signature", open_body)

    def test_physical_consumer_maps_signed_vnode_code(self) -> None:
        self.assertIn("cnd_consumer_map_physical_payload(", self.hook)
        self.assertIn('"__cndhook"', self.hook)
        self.assertIn("F_CHECK_LV", self.hook)
        self.assertIn("MAP_PRIVATE | MAP_FIXED", self.hook)
        self.assertIn("if (!remote_call_uses_lab_backend())", self.hook)
        self.assertIn('"physical-signed-vnode-remotecall"', self.hook)

    def test_library_validation_is_advisory_to_exact_signed_mmap(self) -> None:
        self.assertNotIn("libraryPolicyDenied", self.hook)
        self.assertIn(
            "bool policyFallbackUsed = !libraryValidated && checkWritten",
            self.hook,
        )
        self.assertIn(
            "bool executableMapPermitted = libraryValidated || policyFallbackUsed",
            self.hook,
        )
        self.assertIn("libraryValidationPolicyFallbackUsed", self.hook)

    def test_physical_consumer_consumes_executable_sandbox_extension(self) -> None:
        self.assertIn('"com.apple.sandbox.executable"', self.hook)
        self.assertIn('"sandbox_extension_issue_file"', self.hook)
        self.assertIn('"sandbox_extension_consume"', self.hook)
        issue = self.hook.index('"sandbox_extension_issue_file"')
        target = self.hook.index(
            "RemoteCallSession *session = [[RemoteCallSession alloc]",
            issue,
        )
        consume = self.hook.index('"sandbox_extension_consume"', target)
        install = self.hook.index(
            "CNDIconServicesConsumerHookInstallInCurrentSession(", consume
        )
        self.assertLess(issue, target)
        self.assertLess(target, consume)
        self.assertLess(consume, install)
        self.assertIn("executableTokenConsumed", self.hook)
        self.assertIn("executable-grant=%@/%@ handle=%lld", self.hook)

    def test_fchecklv_argument_uses_target_owned_context_page(self) -> None:
        start = self.hook.index("static bool cnd_consumer_map_physical_payload(")
        end = self.hook.index("static bool cnd_consumer_prepare_method", start)
        mapper = self.hook[start:end]
        self.assertIn("remoteBase + contextOffset", mapper)
        self.assertIn("mappingLength - contextOffset >= validationStorageLength", mapper)
        self.assertNotIn('"malloc", sizeof(fchecklv_t)', mapper)
        self.assertNotIn('"free", checkAddress', mapper)

    def test_fchecklv_has_target_owned_policy_error_output(self) -> None:
        start = self.hook.index("static bool cnd_consumer_map_physical_payload(")
        end = self.hook.index("static bool cnd_consumer_prepare_method", start)
        mapper = self.hook[start:end]
        self.assertIn("validationMessageCapacity = 512", mapper)
        self.assertIn(".lv_error_message_size = validationMessageCapacity", mapper)
        self.assertIn(
            ".lv_error_message = (void *)(uintptr_t)validationMessageAddress",
            mapper,
        )
        self.assertIn('"memset", validationMessageAddress, 0', mapper)
        self.assertIn("lv-message=%s", mapper)

    def test_physical_consumer_does_not_shmem_read_file_backed_code(self) -> None:
        start = self.hook.index("static bool cnd_consumer_map_physical_payload(")
        end = self.hook.index("static bool cnd_consumer_prepare_method", start)
        mapper = self.hook[start:end]
        self.assertNotIn("codeReadback", mapper)
        self.assertNotIn("remote_read(\n        remoteBase", mapper)
        self.assertIn("target-side execution", mapper)

    def test_live_stable_timeout_keeps_exception_port_owned(self) -> None:
        self.assertIn("syntheticCallInFlight", self.remote_call)
        self.assertIn(
            "deferTeardownForInFlightSyntheticCall", self.remote_call
        )
        self.assertIn(
            "Refusing synchronous teardown while a synthetic call is still in flight",
            self.remote_call,
        )
        self.assertIn(
            "Delayed synthetic call completion drained safely",
            self.remote_call,
        )
        self.assertIn(
            "[session deferTeardownForInFlightSyntheticCall]", self.hook
        )

    def test_physical_consumer_is_bound_to_exact_pid_and_task(self) -> None:
        self.assertIn("CNDIconServicesConsumerHookInstallForPID", self.hook)
        self.assertIn("sessionPID == expectedPID", self.hook)
        self.assertIn("sessionTask == expectedTask", self.hook)
        self.assertIn("proc_find(expectedPID) == expectedProc", self.hook)
        self.assertIn("proc_task(expectedProc) == expectedTask", self.hook)

    def test_physical_springboard_switcher_uses_one_signed_imp_session(self) -> None:
        start = self.hook.index(
            "cnd_consumer_install_physical_flat_image_redirect("
        )
        end = self.hook.index(
            "typedef struct {\n    uint32_t flagsBefore;", start
        )
        body = self.hook[start:end]
        self.assertEqual(
            body.count("RemoteCallSession *session ="), 1
        )
        self.assertEqual(
            body.count("remote_call_with_session(session, ^{"), 1
        )
        self.assertIn('"SBFluidSwitcherSpaceTitleItem"', body)
        self.assertIn('"setImageView:"', body)
        self.assertIn('"setImage:"', body)
        self.assertIn(
            '"SBFluidSwitcherSpaceTitleItemController"', body
        )
        self.assertIn('"_iconViewForDisplayItem:"', body)
        self.assertIn('"_iconImageForDisplayItem:"', body)
        self.assertIn('.expectedTypes = "v24@0:8@16"', body)
        self.assertIn('.expectedTypes = "@24@0:8@16"', body)
        self.assertIn("for (NSUInteger reverse = redirectCount;", body)
        self.assertIn("redirect->installedByThisCall", body)
        self.assertIn('@"switcherRedirectsVerified"', body)

    def test_springboard_reconstruction_precedes_clock_calendar_sources(self) -> None:
        start = self.hook.index(
            "cnd_consumer_install_physical_flat_image_redirect("
        )
        end = self.hook.index(
            "typedef struct {\n    uint32_t flagsBefore;", start
        )
        installer = self.hook[start:end]
        self.assertEqual(installer.count("RemoteCallSession *session ="), 1)
        self.assertEqual(
            installer.count("remote_call_with_session(session, ^{"), 1
        )
        dynamic_sources = installer.index(
            "themer_set_static_dynamic_icon_overlays_in_session("
        )
        refresh = installer.index(
            "themer_refresh_springboard_iconservices_cache_in_session()"
        )
        self.assertLess(refresh, dynamic_sources)
        self.assertIn('@"staticIconsVerified"', installer)

    def test_dynamic_icons_use_their_exact_measured_source_boundaries(self) -> None:
        start = self.themer.index(
            "themer_configure_clock_calendar_sources_in_session("
        )
        end = self.themer.index(
            "themer_set_static_dynamic_icon_overlays_in_session(", start
        )
        sources = self.themer[start:end]
        self.assertIn('"imageSetForMetrics:imageAppearance:"', self.themer)
        self.assertIn("themer_clock_image_set_for_appearance(", sources)
        self.assertIn('"SBHCalendarApplicationIcon"', sources)
        self.assertIn('"makeIconLayerWithInfo:traitCollection:context:options:"', sources)
        self.assertIn(
            '"cnd_sbr_calendar_image_original_imp", false',
            sources,
        )
        self.assertIn(
            '"cnd_sbr_calendar_layer_original_imp", false', sources
        )
        self.assertNotIn('"__cnd_calendar_background"', sources)
        self.assertNotIn("themer_apply_static_calendar_background(", sources)
        self.assertIn(
            "themer_configure_calendar_provider_source(installCalendar)",
            sources,
        )
        self.assertIn("themer_configure_clock_base_source(", sources)
        self.assertIn('"clock-safe-generic-redirect"', sources)
        self.assertIn("installSafeSpringBoardClockRedirect", sources)
        self.assertIn('"dedicated-clock-route=0 "', sources)
        self.assertIn('"SBIconImageView", "iconForImage"', sources)
        self.assertIn(
            '"cnd_sbr_clock_icon_for_image_original_imp",\n'
            "        installSafeSpringBoardClockRedirect",
            sources,
        )
        self.assertIn('"__cnd_clock_background"', sources)
        self.assertNotIn("themer_apply_live_clock_background(", sources)
        self.assertIn("themer_make_clock_base_descriptor(", self.themer)
        self.assertIn(
            '"9E1D8C88-D314-329D-BE0F-1D262142B74B"',
            self.themer,
        )
        self.assertIn('"com.apple.application-icon.clock.base"', self.themer)
        self.assertIn('"CNDClockBaseSourceLeafV1_"', self.themer)
        self.assertIn('"objc_getAssociatedObject"', self.themer)
        self.assertIn('"setImage:forDescriptor:"', self.themer)
        self.assertIn('"updateImageAnimated:"', self.themer)
        self.assertIn('"clock-base-source-ready"', self.themer)
        self.assertIn('@"calendarProviderSourceVerified"', sources)
        self.assertIn(
            '@"transitionDescriptorsPreserved": @YES', self.themer
        )
        self.assertIn(
            '@"viewScanUsed": @([clockBackgroundResult[@"viewScanUsed"]',
            sources,
        )
        self.assertNotIn("themer_reload_calendar_model_icon()", sources)
        self.assertNotIn("themer_reload_clock_calendar_model_icons()", sources)
        self.assertNotIn('"clock-background-generic-icon"', sources)
        self.assertIn(
            '"ClockIconBackgroundSquare@2x~iphone.png"',
            SNOWBOARD_LITE.read_text(encoding="utf-8"),
        )
        self.assertIn("themer_clock_backup_or_apply_image_set(", sources)
        clock_view_start = self.themer.index(
            "themer_collect_exact_clock_image_views("
        )
        clock_view_end = self.themer.index(
            "themer_configure_clock_base_source(", clock_view_start
        )
        clock_view_discovery = self.themer[
            clock_view_start:clock_view_end
        ]
        self.assertIn(
            '"displayedIconViewForIcon:"', clock_view_discovery
        )
        self.assertIn(
            '"applicationIconForBundleIdentifier:"',
            clock_view_discovery,
        )
        self.assertNotIn(
            "= sb_collect_views_in_windows(", clock_view_discovery
        )
        self.assertIn(
            '"cnd_sbr_clock_image_set_states_v1"', self.themer
        )
        self.assertIn(
            'themer_session_dictionary_object(state, "originalImages")',
            self.themer,
        )
        self.assertIn(
            "uint64_t dynamicRedirectRegistry =\n"
            "        themer_dynamic_redirect_registry(\n"
            "            installStaticClockRedirect || installSafeSpringBoardClockRedirect)",
            sources,
        )
        self.assertIn(
            "uint64_t clockImageSetRegistry =\n"
            "        themer_clock_image_set_registry(installClockHands)",
            sources,
        )
        self.assertNotIn(
            '"cnd_sbr_clock_original_image_set"', self.themer
        )
        self.assertIn(
            '"cnd_sbr_dynamic_redirect_backups_v1"', self.themer
        )
        process_getter_start = self.themer.index(
            "themer_spotlight_associated_process_object("
        )
        process_getter_end = self.themer.index(
            "themer_spotlight_commit_process_object(",
            process_getter_start,
        )
        process_getter = self.themer[
            process_getter_start:process_getter_end
        ]
        self.assertIn(
            'themer_remote_symbol_addr(\n        "objc_getAssociatedObject")',
            process_getter,
        )
        self.assertIn("themer_add_method(processClass", process_getter)
        self.assertIn(
            "return r_msg2_main(processInfo, keyName", process_getter
        )
        self.assertNotIn(
            'r_dlsym_call(R_TIMEOUT, "objc_getAssociatedObject"',
            process_getter,
        )
        dynamic_start = self.themer.index(
            "themer_set_remote_associated_object("
        )
        dynamic_end = self.themer.index(
            "themer_set_static_dynamic_icon_overlays_in_session("
        )
        dynamic_sources = self.themer[dynamic_start:dynamic_end]
        self.assertNotIn(
            'r_dlsym_call(R_TIMEOUT, "objc_getAssociatedObject"',
            dynamic_sources,
        )
        self.assertNotIn(
            "themer_remote_associated_object(", dynamic_sources
        )
        self.assertNotIn("themer_pin_static_dynamic_child_overlay(", sources)
        self.assertNotIn("themer_static_dynamic_overlay_matching_icon_views(", sources)
        self.assertNotIn('sel_registerName("windows")', sources)
        self.assertNotIn("RemoteCallSession *", sources)

        self.assertNotIn("themer_apply_live_clock_background", self.themer)
        self.assertNotIn("themer_apply_static_calendar_background", self.themer)

    def test_calendar_provider_bridge_preserves_apple_size_and_layer_paths(self) -> None:
        start = self.themer.index(
            "themer_configure_calendar_provider_source(bool install)"
        )
        end = self.themer.index(
            "themer_configure_clock_calendar_sources_in_session(", start
        )
        calendar = self.themer[start:end]
        self.assertIn('"SBCalendarIconImageProvider"', calendar)
        self.assertIn('"preparedISIcon"', calendar)
        self.assertIn('"@16@0:8"', calendar)
        self.assertIn('"CNDCalendarPreparedSourceV1_"', self.themer)
        self.assertIn('"objc_getAssociatedObject"', self.themer)
        self.assertIn('"ISBundleIdentifierIcon"', self.themer)
        self.assertIn('"findOrRegisterIcon:"', self.themer)
        self.assertIn('"com.apple.mobilecal"', self.themer)
        self.assertIn('"prepareImageForDescriptor:"', self.themer)
        self.assertIn('CUIKIcon/CUIKDefaultIconGenerator', calendar)
        self.assertIn('"reloadIconImage"', calendar)
        self.assertNotIn("pass < 2", calendar)
        self.assertIn('@"fastPath": @YES', calendar)
        self.assertIn("reloadPasses == 1", calendar)
        self.assertIn('@"calendar-provider-source-ready"', calendar)
        self.assertIn('@"requiresVisibleView": @NO', calendar)
        self.assertIn('@"viewScanUsed": @NO', calendar)
        self.assertIn('@"viewPaintUsed": @NO', calendar)
        self.assertIn('@"persistentDescriptorMatrixPreserved": @YES', calendar)
        self.assertNotIn('sel_registerName("windows")', calendar)
        self.assertNotIn("RemoteCallSession *", calendar)

    def test_spotlight_clock_uses_static_generic_view_factory(self) -> None:
        start = self.themer.index(
            "themer_configure_clock_calendar_sources_in_session("
        )
        end = self.themer.index(
            "themer_set_static_dynamic_icon_overlays_in_session(", start
        )
        sources = self.themer[start:end]
        self.assertIn('"spotlight-clock-static-view-class"', sources)
        self.assertIn(
            '"SBHClockApplicationIcon", "iconImageViewClassForLocation:"',
            sources,
        )
        self.assertIn(
            '"SBIcon", "iconImageViewClassForLocation:", "#24@0:8@16"',
            sources,
        )
        self.assertIn(
            '"cnd_sbr_spotlight_clock_view_class_original_imp"', sources
        )
        self.assertIn(
            "useStaticClockPresentation && installClock", sources
        )
        self.assertIn('@"spotlight-static-clock-ready"', sources)
        self.assertIn('@"requiresVisibleLeaf": @NO', sources)
        self.assertIn(
            '@"replacementSource": '
            '@"com.apple.mobiletimer/persistent-descriptor-matrix"',
            sources,
        )
        self.assertIn(
            "themer_configure_clock_base_source(nil, false)", sources
        )
        self.assertIn(
            "bool installClockHands = !useStaticClockPresentation", sources
        )
        self.assertIn(
            '@"existingRowsRequireReconstruction": @(installClock)', sources
        )

        hook_start = self.hook.index(
            "cnd_consumer_install_physical_flat_image_redirect("
        )
        hook_end = self.hook.index(
            "typedef struct {\n    uint32_t flagsBefore;", hook_start
        )
        installer = self.hook[hook_start:hook_end]
        self.assertIn(
            'BOOL isSpotlight = [processName isEqualToString:@"Spotlight"]',
            installer,
        )
        self.assertIn(
            "staticIconDataByBundle ?: @{}, isSpotlight", installer
        )

    def test_spotlight_installs_independent_dynamic_sources(self) -> None:
        remix = (INSTALLER / "CNDSnowBoardRemix.m").read_text(encoding="utf-8")
        start = remix.index("+ (NSDictionary<NSString *, id> *)repairSpotlightPresentation")
        end = remix.index("static NSString *CNDRemixAuditHashClassification", start)
        repair = remix[start:end]
        self.assertIn('CNDIconServicesConsumerLifecycleRepairProcess(\n            @"Spotlight"', repair)
        self.assertIn(
            "CNDIconServicesConsumerLifecycleSetStaticDynamicIconData(staticIcons)",
            repair,
        )
        self.assertIn('@"transparencyVerified"', repair)
        self.assertIn('@"dynamicIconSourcesAttempted"] =', repair)
        self.assertIn('@"dynamicIconSourcesSupported"] = @YES', repair)
        self.assertIn('[sourceResult[@"ok"] boolValue]', repair)
        self.assertNotIn('@"dynamic-source-replacement-unavailable"', repair)
        self.assertNotIn('@"SpringBoard"', repair)

    def test_partial_dynamic_work_keeps_verified_transparency_pid(self) -> None:
        start = self.lifecycle.index("BOOL transparencyReady =")
        end = self.lifecycle.index("CNDIconServicesConsumerLifecycleRepairProcess(NSString", start)
        manual = self.lifecycle[start:end]
        self.assertIn('[install[@"transparencyVerified"] boolValue]', manual)
        self.assertIn("if (transparencyReady)", manual)
        self.assertIn("state.installedPID = pid", manual)
        self.assertIn('@"presentation-ready-tweaks-partial"', manual)

    def test_springboard_refresh_reloads_canonical_and_live_leaf_icons(self) -> None:
        start = self.themer.index(
            "bool themer_refresh_springboard_iconservices_cache_in_session(void)"
        )
        end = self.themer.index(
            "static int themer_graft_icon_models_for_theme_options", start
        )
        refresh = self.themer[start:end]
        self.assertIn(
            '"applicationIconForBundleIdentifier:"', refresh
        )
        self.assertIn(
            '"leafIconsUniquedByApplicationBundleIdentifier"', refresh
        )
        self.assertIn("reloadIdentifierSet", refresh)
        self.assertIn("matchedReloadIdentifiers", refresh)
        self.assertIn("themer_add_unique(reloadIconObjects", refresh)
        self.assertIn('"reloadIconImage"', refresh)
        self.assertNotIn("RemoteCallSession *", refresh)

    def test_springboard_refresh_has_complete_bounded_cache_inventory(self) -> None:
        start = self.themer.index(
            "bool themer_refresh_springboard_iconservices_cache_in_session(void)"
        )
        end = self.themer.index(
            "static int themer_graft_icon_models_for_theme_options", start
        )
        refresh = self.themer[start:end]
        for getter in (
            '"iconImageCache"',
            '"notificationIconImageCache"',
            '"NCUIMappedImageCache"',
            '"sharedCache"',
            '"tableUIIconImageCache"',
            '"appSwitcherHeaderIconImageCache"',
            '"folderIconImageCache"',
            '"rootFolderController"',
            '"iconTableViewController"',
            '"searchResultsController"',
        ):
            self.assertIn(getter, refresh)
        self.assertIn("libraryCaches", refresh)
        self.assertIn("libraryTableCaches", refresh)
        self.assertIn("folderSourceCache", refresh)
        self.assertIn("folderSourcePurgeIssued", refresh)
        self.assertIn("rootFolderControllerCache", refresh)
        self.assertIn("rootFolderCacheRebound", refresh)
        self.assertIn("CACHE_CAP = 16", refresh)

    def test_springboard_refresh_reacquires_owner_caches_after_reset(self) -> None:
        start = self.themer.index(
            "bool themer_refresh_springboard_iconservices_cache_in_session(void)"
        )
        end = self.themer.index(
            "static int themer_graft_icon_models_for_theme_options", start
        )
        refresh = self.themer[start:end]
        capture = refresh.index("imageCacheBeforeReset = imageCache")
        reset = refresh.index(
            'r_msg2_main(iconManager, "resetAllIconImageCaches"', capture
        )
        reacquire = refresh.index("imageCache = resetIssued", reset)
        explicit = refresh.index("uint64_t explicitCaches", reacquire)
        purge = refresh.index('cache, "purgeAllCachedImages"', explicit)
        self.assertLess(capture, reset)
        self.assertLess(reset, reacquire)
        self.assertLess(reacquire, explicit)
        self.assertLess(explicit, purge)
        for assignment in (
            "notificationCache = resetIssued",
            "notificationMappedCache = resetIssued",
            "tableUICache = resetIssued",
            "appSwitcherCache = resetIssued",
            "folderImageCache = resetIssued",
            "rootFolderController = resetIssued",
        ):
            self.assertIn(assignment, refresh[reacquire:explicit])
        self.assertIn("[SBR_CACHE_POINTERS]", refresh)
        self.assertIn("themer_pointer_is_covered", refresh)

    def test_springboard_refresh_rebinds_root_cache_after_purges(self) -> None:
        start = self.themer.index(
            "bool themer_refresh_springboard_iconservices_cache_in_session(void)"
        )
        end = self.themer.index(
            "static int themer_graft_icon_models_for_theme_options", start
        )
        refresh = self.themer[start:end]
        reset = refresh.index('"resetAllIconImageCaches"')
        reacquire = refresh.index("rootFolderController = resetIssued", reset)
        purge = refresh.index('cache, "purgeAllCachedImages"', reacquire)
        rebind = refresh.index(
            'rootFolderController, "setIconImageCache:"', purge
        )
        generation = refresh.index(
            "stage=reload-themed-icon-generations", rebind
        )
        self.assertLess(reset, reacquire)
        self.assertLess(reacquire, purge)
        self.assertLess(purge, rebind)
        self.assertLess(rebind, generation)
        self.assertIn('"v24@0:8@16"', refresh[rebind - 220:rebind + 220])
        self.assertIn("rootFolderControllerCache == imageCache", refresh)
        self.assertIn("rootFolderCacheRebound && reloadIconsOK", refresh)

    def test_springboard_refresh_abi_gates_private_mutators(self) -> None:
        start = self.themer.index(
            "bool themer_refresh_springboard_iconservices_cache_in_session(void)"
        )
        end = self.themer.index(
            "static int themer_graft_icon_models_for_theme_options", start
        )
        refresh = self.themer[start:end]
        expected = {
            "resetAllIconImageCaches": "v16@0:8",
            "purgeAllCachedImages": "v16@0:8",
            "removeAllObjects": "v16@0:8",
            "allKeys": "@16@0:8",
            "reloadIconImage": "v16@0:8",
            "rebuildAllCachedFolderImages": "v16@0:8",
            "_reloadAppIcons": "v16@0:8",
            "_reloadVisibleCells": "v16@0:8",
            "_enqueueAppLibraryUpdate": "v16@0:8",
            "_updateDisplayItemIcons": "v16@0:8",
            "_performUpdateHandler": "v16@0:8",
            "setTitleItems:animated:": "v28@0:8@16B24",
            "_reloadLeadingNotificationRequestsForStackedNotificationGroupListsWithForceReloadAllStacks:": "v20@0:8B16",
            "allNotificationGroups": "@16@0:8",
            "allNotificationRequests": "@16@0:8",
            "_currentCellForNotificationRequest:": "@24@0:8@16",
            "_updateVisibleIcons": "v16@0:8",
            "relayout": "B16@0:8",
        }
        for selector, encoding in expected.items():
            self.assertRegex(
                refresh,
                r"themer_springboard_method_encoding_is\("
                r"[\s\S]{0,180}?" + re.escape(f'"{selector}"') +
                r"[\s\S]{0,80}?" + re.escape(f'"{encoding}"'),
            )

    def test_springboard_refresh_logs_one_result_per_target_surface(self) -> None:
        start = self.themer.index(
            "bool themer_refresh_springboard_iconservices_cache_in_session(void)"
        )
        end = self.themer.index(
            "static int themer_graft_icon_models_for_theme_options", start
        )
        refresh = self.themer[start:end]
        for surface in (
            "home",
            "folder-preview",
            "app-switcher",
            "app-library-category",
            "app-library-list",
            "notifications",
            "launch-return",
        ):
            self.assertEqual(
                refresh.count(f"[SBR_SURFACE] surface={surface}"), 1
            )
        self.assertNotIn('"updateImageForIcon:"', refresh)
        self.assertNotIn('"setActive:"', refresh)

    def test_switcher_refresh_recomputes_materialized_titles_after_purge(self) -> None:
        start = self.themer.index(
            "bool themer_refresh_springboard_iconservices_cache_in_session(void)"
        )
        end = self.themer.index(
            "static int themer_graft_icon_models_for_theme_options", start
        )
        refresh = self.themer[start:end]
        purge = refresh.index("appSwitcherPurgeIssued")
        content = refresh.index('"contentViewController"', purge)
        title_map = refresh.index('"_appLayoutToTitleItemController"')
        update_icons = refresh.index('"_updateDisplayItemIcons"', title_map)
        visible_items = refresh.index('"_visibleItemContainers"', update_icons)
        visible_overlay = refresh.index(
            '"_visibleOverlayAccessoryViews"', visible_items
        )
        visible_underlay = refresh.index(
            '"_visibleUnderlayAccessoryViews"', visible_overlay
        )
        clear_titles = refresh.index(
            'consumer, "setTitleItems:animated:"', visible_underlay
        )
        update_handler = refresh.index(
            'controller, "_performUpdateHandler"', clear_titles
        )
        self.assertLess(purge, title_map)
        self.assertLess(content, title_map)
        self.assertLess(title_map, update_icons)
        self.assertLess(update_icons, visible_items)
        self.assertLess(visible_items, visible_overlay)
        self.assertLess(visible_overlay, visible_underlay)
        self.assertLess(visible_underlay, clear_titles)
        self.assertLess(clear_titles, update_handler)
        self.assertIn("SWITCHER_TITLE_CONTROLLER_CAP = 128", refresh)
        self.assertIn("switcherMaterializedConsumers[384]", refresh)
        self.assertIn(
            "switcherMaterializedConsumerCleared ==",
            refresh,
        )
        self.assertIn("switcherMaterializedConsumersTruncated", refresh)
        self.assertLess(update_icons, update_handler)
        self.assertIn("titleControllerUpdated == titleControllerEligible", refresh)

    def test_springboard_refresh_orders_generation_folder_library_and_relayout(self) -> None:
        start = self.themer.index(
            "bool themer_refresh_springboard_iconservices_cache_in_session(void)"
        )
        end = self.themer.index(
            "static int themer_graft_icon_models_for_theme_options", start
        )
        refresh = self.themer[start:end]
        purge = refresh.index("stage=purge-caches")
        generation = refresh.index("stage=reload-themed-icon-generations")
        folder = refresh.index("stage=rebuild-folders")
        library = refresh.index("stage=reload-app-library")
        table = refresh.index("stage=reload-app-library-table")
        relayout = refresh.index("stage=relayout-home-library")
        self.assertLess(purge, generation)
        self.assertLess(generation, folder)
        self.assertLess(folder, library)
        self.assertLess(library, table)
        self.assertLess(table, relayout)

    def test_springboard_refresh_directly_reloads_app_library_table(self) -> None:
        start = self.themer.index(
            "bool themer_refresh_springboard_iconservices_cache_in_session(void)"
        )
        end = self.themer.index(
            "static int themer_graft_icon_models_for_theme_options", start
        )
        refresh = self.themer[start:end]
        self.assertIn('"iconTableViewController"', refresh)
        self.assertIn('"containerViewController"', refresh)
        self.assertIn('"searchResultsController"', refresh)
        self.assertIn("libraryTableCachesPurged", refresh)
        purge = refresh.index('"purgeAllCachedImages"')
        table_stage = refresh.index('stage=reload-app-library-table')
        reload_apps = refresh.index('"_reloadAppIcons"', table_stage)
        reload_visible = refresh.index('"_reloadVisibleCells"', table_stage)
        self.assertLess(purge, table_stage)
        self.assertLess(table_stage, reload_apps)
        self.assertLess(reload_apps, reload_visible)
        self.assertIn("libraryTableRefreshOK", refresh)
        self.assertNotIn('"setActive:"', refresh)
        self.assertIn("view-tree-walk=0", refresh)

    def test_notification_refresh_purges_real_cache_and_refetches_live_rows(self) -> None:
        start = self.themer.index(
            "bool themer_refresh_springboard_iconservices_cache_in_session(void)"
        )
        end = self.themer.index(
            "static int themer_graft_icon_models_for_theme_options", start
        )
        refresh = self.themer[start:end]
        mapped = refresh.index('"NCUIMappedImageCache"')
        reset = refresh.index('"resetAllIconImageCaches"')
        reacquire = refresh.index("notificationMappedCache = resetIssued", reset)
        remove_all = refresh.index('"removeAllObjects"', reacquire)
        barrier = refresh.index(
            'notificationMappedCache, "allKeys"', remove_all
        )
        section_reload = refresh.index(
            '"_reloadLeadingNotificationRequestsForStackedNotificationGroupListsWithForceReloadAllStacks:"',
            barrier,
        )
        groups = refresh.index('"allNotificationGroups"', section_reload)
        requests = refresh.index('"allNotificationRequests"', groups)
        current_cell = refresh.index(
            '"_currentCellForNotificationRequest:"', requests
        )
        clear_image = refresh.index('imageView, "setImage:"', current_cell)
        refetch = refresh.index('"_updateVisibleIcons"', clear_image)
        self.assertLess(mapped, reset)
        self.assertLess(reset, reacquire)
        self.assertLess(reacquire, remove_all)
        self.assertLess(remove_all, barrier)
        self.assertLess(barrier, section_reload)
        self.assertLess(section_reload, groups)
        self.assertLess(groups, requests)
        self.assertLess(requests, current_cell)
        self.assertLess(current_cell, clear_image)
        self.assertLess(clear_image, refetch)
        self.assertIn("notificationMappedKeyCountAfter == 0", refresh)
        self.assertIn("NOTIFICATION_SECTION_CAP = 16", refresh)
        self.assertIn("NOTIFICATION_GROUP_CAP = 128", refresh)
        self.assertIn("NOTIFICATION_REQUEST_CAP = 256", refresh)
        self.assertIn("notificationBadgedIconEligible ==", refresh)
        self.assertIn("view-tree-walk=0", refresh)
        self.assertNotIn('sel_registerName("windows")', refresh)

    def test_springboard_applied_state_audit_only_reads_live_consumers(self) -> None:
        start = self.themer.index(
            "themer_audit_springboard_iconservices_consumers_in_session("
        )
        end = self.themer.index(
            "bool themer_refresh_springboard_iconservices_cache_in_session(void)",
            start,
        )
        audit = self.themer[start:end]
        self.assertIn('"applicationIconForBundleIdentifier:"', audit)
        self.assertIn('"leafIconsUniquedByApplicationBundleIdentifier"', audit)
        self.assertIn('"_displayItems"', audit)
        self.assertIn('"_displayItemToIcon"', audit)
        self.assertIn('@"mutationsIssued": @NO', audit)
        for mutator in (
            '"reloadIconImage"',
            '"purgeAllImages"',
            '"_performUpdateHandler"',
            '"_updateDisplayItemIcons"',
            'method_setImplementation',
        ):
            self.assertNotIn(mutator, audit)

    def test_springboard_audit_uses_one_scoped_remote_session(self) -> None:
        start = self.hook.index("CNDIconServicesConsumerHookAuditSpringBoard(")
        audit = self.hook[start:]
        self.assertEqual(audit.count("RemoteCallSession *session ="), 1)
        self.assertEqual(audit.count("remote_call_with_session(session, ^{"), 1)
        self.assertIn(
            "themer_audit_springboard_iconservices_consumers_in_session(",
            audit,
        )
        self.assertIn('@"mutationsIssued"] = @NO', audit)

    def test_lifecycle_keeps_vm_direct_and_physical_remotecall_routes(self) -> None:
        self.assertIn("remote_call_lab_backend_opted_in() ||", self.lifecycle)
        self.assertIn("!cnd_lab_direct_task_active();", self.lifecycle)
        self.assertIn(
            "CNDIconServicesConsumerHookInstallForPIDWithOptions(",
            self.lifecycle,
        )
        self.assertIn("CNDIconServicesConsumerKernelInstallForPID(", self.lifecycle)
        hook_call = self.lifecycle.index(
            "CNDIconServicesConsumerHookInstallForPIDWithOptions("
        )
        kernel_call = self.lifecycle.index(
            "CNDIconServicesConsumerKernelInstallForPID("
        )
        route = self.lifecycle.rfind("usesRemoteCall", 0, hook_call)
        self.assertGreaterEqual(route, 0)
        self.assertLess(hook_call, kernel_call)

    def test_watcher_polls_spotlight_only(self) -> None:
        tick_start = self.lifecycle.index(
            "static void CNDConsumerLifecycleTick(void)"
        )
        tick_end = self.lifecycle.index(
            "static void CNDConsumerLifecycleAccelerateSpotlightLocked",
            tick_start,
        )
        tick = self.lifecycle[tick_start:tick_end]
        self.assertIn('CNDConsumerLifecycleState(@"Spotlight")', tick)
        self.assertNotIn('CNDConsumerLifecycleState(@"SpringBoard")', tick)
        self.assertNotIn("NextSpringBoardPoll", self.lifecycle)
        self.assertNotIn("SpringBoardToken", self.lifecycle)

    def test_presentation_reconciliation_is_status_only(self) -> None:
        remix = (INSTALLER / "CNDSnowBoardRemix.m").read_text(encoding="utf-8")
        start = remix.index("CNDRemixReconcilePresentationLifecycle(void)")
        end = remix.index("static NSURL *CNDRemixIndexURL(void)", start)
        reconcile = remix[start:end]
        self.assertIn("CNDIconServicesConsumerLifecycleStatus()", reconcile)
        self.assertNotIn("CNDIconServicesConsumerLifecycleStart", reconcile)
        self.assertNotIn("CNDIconServicesConsumerLifecycleStop", reconcile)

    def test_initial_apply_cache_refresh_has_reversible_experiment_gate(self) -> None:
        remix = (INSTALLER / "CNDSnowBoardRemix.m").read_text(encoding="utf-8")
        self.assertIn(
            "static const BOOL CNDRemixEnableSpringBoardCacheInvalidation = NO;",
            remix,
        )
        start = remix.index("CNDRemixRunInitialCacheRefresh(void)")
        end = remix.index("static NSURL *CNDRemixIndexURL(void)", start)
        one_shot = remix[start:end]
        disabled = one_shot.index(
            "if (!CNDRemixEnableSpringBoardCacheInvalidation)"
        )
        refresh = one_shot.index(
            "CNDIconServicesConsumerLifecycleRefreshSpringBoardCaches()"
        )
        self.assertLess(disabled, refresh)
        self.assertIn('@"stage": @"cache-invalidation-disabled-experiment"', one_shot)
        self.assertIn('@"cacheInvalidationIssued": @NO', one_shot)
        self.assertIn("CNDIconServicesConsumerLifecycleRefreshSpringBoardCaches()", one_shot)
        self.assertNotIn("CNDIconServicesConsumerLifecycleRepair", one_shot)
        self.assertNotIn("CNDIconServicesConsumerLifecycleSetStaticDynamicIconData", one_shot)
        self.assertNotIn("kSettingsSnowBoardRemixInstallConsumerMappings", one_shot)
        self.assertIn('@"transparencyRepairCompleted": @NO', one_shot)
        self.assertIn('@"dynamicIconRepairCompleted": @NO', one_shot)
        self.assertNotIn("CNDIconServicesConsumerLifecycleStart", one_shot)
        self.assertNotIn("dispatch_async", one_shot)
        self.assertIn('@"completed": @YES', one_shot)
        self.assertIn('@"watcherStarted": @NO', one_shot)

    def test_enabled_apply_path_still_completes_springboard_cache_refresh(self) -> None:
        remix = (INSTALLER / "CNDSnowBoardRemix.m").read_text(encoding="utf-8")
        start = remix.index("CNDRemixRunInitialCacheRefresh(void)")
        end = remix.index("static NSURL *CNDRemixIndexURL(void)", start)
        one_shot = remix[start:end]
        self.assertIn(
            "CNDIconServicesConsumerLifecycleRefreshSpringBoardCaches()",
            one_shot,
        )
        self.assertIn('@"springBoardCacheRefreshCompleted": @(ok)', one_shot)
        self.assertIn('@"springBoardCacheRefreshQueued": @NO', one_shot)
        self.assertIn('@"cacheInvalidationIssued": @YES', one_shot)

    def test_restore_always_runs_the_selected_springboard_repair(self) -> None:
        remix = (INSTALLER / "CNDSnowBoardRemix.m").read_text(encoding="utf-8")
        start = remix.index(
            "CNDRemixRestoreSpringBoardPresentationIfNeeded("
        )
        end = remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals(",
            start,
        )
        restore = remix[start:end]
        self.assertIn("CNDRemixEnableSpringBoardCacheInvalidation", restore)
        self.assertNotIn("springboard-session-not-required", restore)
        self.assertIn(
            "CNDIconServicesConsumerLifecycleRepairAfterThemeMutation(", restore
        )
        self.assertIn("CNDIconServicesConsumerLifecycleRepairProcess(", restore)
        self.assertIn('@"disabled-experiment"', restore)

    def test_restore_separates_persistent_cleanliness_from_final_result(self) -> None:
        remix = (INSTALLER / "CNDSnowBoardRemix.m").read_text(encoding="utf-8")
        self.assertIn('journal[@"state"] = allVerified &&', remix)
        self.assertIn('@"persistent-stock-verified"', remix)
        self.assertIn("if (appVerified) persistentClean++;", remix)
        self.assertIn('@"persistentDataClean"', remix)
        self.assertIn('@"presentationCompleted": @YES', remix)
        self.assertIn(
            "BOOL persistentRecoveryOK = persistentDataClean && !cancelled && failed == 0;",
            remix,
        )
        self.assertIn("BOOL cleanupOK = sessionClosed && presentationOK;", remix)
        self.assertIn("CNDRemixCoordinatorResult(persistentRecoveryOK,", remix)
        self.assertIn("CNDRemixJournalRepresentsDirtyPersistentData", remix)

    def test_cache_only_refresh_does_not_install_presentation_redirects(self) -> None:
        self.assertIn(
            "CNDIconServicesConsumerHookRefreshSpringBoardForPID(pid_t pid)",
            self.hook,
        )
        start = self.hook.index(
            "CNDIconServicesConsumerHookRefreshSpringBoardForPID(pid_t pid)"
        )
        end = self.hook.index(
            "CNDIconServicesConsumerHookAuditSpringBoard(", start
        )
        refresh = self.hook[start:end]
        self.assertIn("NO, YES, NO", refresh)
        self.assertIn("remote_call_lab_backend_opted_in()", refresh)
        self.assertIn(
            'cnd_lab_resolve_process_pid(\n            "SpringBoard", &livePID)',
            refresh,
        )
        self.assertLess(
            refresh.index("remote_call_lab_backend_opted_in()"),
            refresh.index("proc_find(pid)"),
        )

    def test_manual_springboard_repair_skips_cache_refresh_but_keeps_static_icons(self) -> None:
        attempt_start = self.lifecycle.index(
            "static void CNDConsumerLifecycleAttemptInstall("
        )
        attempt_end = self.lifecycle.index(
            "static void CNDConsumerLifecyclePollHost(", attempt_start
        )
        attempt = self.lifecycle[attempt_start:attempt_end]
        self.assertIn("afterThemeMutation && isSpringBoard", attempt)
        self.assertIn(
            "isSpringBoard || staticDynamicIcons.count > 0", attempt
        )
        self.assertIn("CNDConsumerLifecycleStaticDynamicIconData()", attempt)

        manual_start = self.lifecycle.index(
            "CNDIconServicesConsumerLifecycleRepairProcess("
        )
        manual = self.lifecycle[manual_start:]
        self.assertIn(
            "CNDConsumerLifecycleRepairProcess(processName, displayScale, NO)",
            manual,
        )

        remix = (INSTALLER / "CNDSnowBoardRemix.m").read_text(encoding="utf-8")
        repair_start = remix.index(
            "+ (NSDictionary<NSString *, id> *)applySpringBoardTweaks"
        )
        repair_end = remix.index(
            "static NSString *CNDRemixAuditHashClassification", repair_start
        )
        repair = remix[repair_start:repair_end]
        stage = repair.index(
            "CNDIconServicesConsumerLifecycleSetStaticDynamicIconData(staticIcons)"
        )
        install = repair.index(
            "CNDIconServicesConsumerLifecycleRepairProcess("
        )
        self.assertLess(stage, install)
        self.assertIn('@"__cnd_clock_hours"', repair)
        self.assertIn('@"clockCalendarSourcesRequested"', repair)

    def test_manual_repairs_do_not_hold_lifecycle_queue_across_target_call(self) -> None:
        start = self.lifecycle.index(
            "CNDConsumerLifecycleRepairProcess(NSString *processName,"
        )
        end = self.lifecycle.index(
            "CNDIconServicesConsumerLifecycleRepairProcess(", start
        )
        manual = self.lifecycle[start:end]
        target_call = manual.index(
            "CNDIconServicesConsumerHookInstallForPIDWithOptions("
        )
        reservation = manual.index(
            "dispatch_sync(CNDConsumerLifecycleQueue(), ^{"
        )
        reservation_end = manual.index("queue-held=no", reservation)
        self.assertLess(reservation, reservation_end)
        self.assertLess(reservation_end, target_call)
        self.assertNotIn("CNDConsumerLifecycleAttemptInstall(state", manual)

    def test_watcher_start_exists_only_behind_explicit_settings_action(self) -> None:
        app_delegate = APP_DELEGATE.read_text(encoding="utf-8")
        settings = SETTINGS.read_text(encoding="utf-8")
        self.assertNotIn("reconcilePresentationLifecycle", app_delegate)
        self.assertNotIn(
            "settings_reconcile_snowboard_remix_presentation_async", settings
        )
        self.assertEqual(
            settings.count("CNDIconServicesConsumerLifecycleStart("), 1
        )
        action = settings.index(
            'isEqualToString:@"sbl-start-kernel-consumer-watcher"'
        )
        start = settings.index(
            "CNDIconServicesConsumerLifecycleStart(", action
        )
        self.assertGreater(start, action)


if __name__ == "__main__":
    unittest.main()
