import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
THEMER = ROOT / "Cyanide" / "tweaks" / "themer.m"
THEMER_HEADER = ROOT / "Cyanide" / "tweaks" / "themer.h"
CONSUMER = ROOT / "Cyanide" / "installer" / "CNDIconServicesConsumerHook.m"
CONSUMER_HEADER = ROOT / "Cyanide" / "installer" / "CNDIconServicesConsumerHook.h"
SETTINGS = ROOT / "Cyanide" / "SettingsViewController.m"


def function_slice(source: str, start: str, end: str) -> str:
    start_index = source.index(start)
    end_index = source.index(end, start_index + len(start))
    return source[start_index:end_index]


class AppLibraryMiniatureRefreshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.themer = THEMER.read_text()
        cls.themer_header = THEMER_HEADER.read_text()
        cls.consumer = CONSUMER.read_text()
        cls.consumer_header = CONSUMER_HEADER.read_text()
        cls.settings = SETTINGS.read_text()
        cls.refresh = function_slice(
            cls.themer,
            "themer_refresh_springboard_app_library_miniatures_in_session(void)",
            "bool themer_refresh_springboard_iconservices_cache_in_session(void)",
        )
        cls.wrapper = function_slice(
            cls.consumer,
            "CNDIconServicesConsumerHookRefreshAppLibraryMiniaturesForPID(pid_t pid)",
            "static BOOL cnd_consumer_remote_method_has_exact_types_for_class",
        )

    def test_focused_refresh_api_is_exported(self):
        self.assertIn(
            "themer_refresh_springboard_app_library_miniatures_in_session",
            self.themer_header,
        )
        self.assertIn(
            "CNDIconServicesConsumerHookRefreshAppLibraryMiniaturesForPID",
            self.consumer_header,
        )

    def test_exact_category_graph_and_themed_targets_are_preflighted(self):
        required = (
            '"folderIconImageCache"',
            '"iconImageCache"',
            '"applicationIconForBundleIdentifier:"',
            '"leafIconsUniquedByApplicationBundleIdentifier"',
            '"isApplicationIcon"',
            '"reloadIconImage"',
            '"rebuildAllCachedFolderImages"',
            '"_reloadAppIcons"',
            '"_enqueueAppLibraryUpdate"',
        )
        for selector in required:
            self.assertIn(selector, self.refresh)
        self.assertIn(
            "themer_springboard_refresh_bundle_identifiers_snapshot()",
            self.refresh,
        )
        self.assertIn('@"com.apple.Sharing.AirDrop"', self.refresh)
        self.assertIn(
            '@"ignoredNonApplicationTargets": ignoredNonApplicationTargets',
            self.refresh,
        )
        self.assertIn("reloadLookupMisses > 0", self.refresh)

    def test_mutation_order_is_purge_reload_rebuild_and_category_update(self):
        purge = self.refresh.index('"purgeAllCachedImages"')
        reload_icon = self.refresh.index('"reloadIconImage"', purge)
        rebuild = self.refresh.index('"rebuildAllCachedFolderImages"', reload_icon)
        reload_pods = self.refresh.index('"_reloadAppIcons"', rebuild)
        enqueue = self.refresh.index('"_enqueueAppLibraryUpdate"', reload_pods)
        self.assertLess(purge, reload_icon)
        self.assertLess(reload_icon, rebuild)
        self.assertLess(rebuild, reload_pods)
        self.assertLess(reload_pods, enqueue)

    def test_refresh_excludes_unrelated_surfaces_and_hail_mary_method_mutation(self):
        forbidden = (
            '"resetAllIconImageCaches"',
            '"_reloadVisibleCells"',
            '"relayout"',
            '"method_setImplementation"',
            '"effectivelyPrefersFlatImageLayers"',
            "SIGKILL",
            '"kill"',
            "kwrite",
        )
        for token in forbidden:
            self.assertNotIn(token, self.refresh)
        self.assertIn('@"managerResetIssued": @NO', self.refresh)
        self.assertIn('@"appLibraryListReloadIssued": @NO', self.refresh)
        self.assertIn('@"objectiveCMethodMutationCount": @0', self.refresh)
        self.assertIn('@"processLifecycleMutationCount": @0', self.refresh)
        self.assertIn('@"sharedCacheWriteCount": @0', self.refresh)

    def test_wrapper_binds_and_rechecks_exact_pid(self):
        self.assertIn("session.pid == pid", self.wrapper)
        self.assertIn("finalIdentityStable", self.wrapper)
        self.assertIn(
            "themer_refresh_springboard_app_library_miniatures_in_session()",
            self.wrapper,
        )
        self.assertNotIn("cnd_consumer_install_physical_flat_image_redirect", self.wrapper)
        self.assertNotIn("method_setImplementation", self.wrapper)
        self.assertNotIn("SIGKILL", self.wrapper)

    def test_refresh_helper_is_retained_but_removed_from_quick_actions(self):
        self.assertRegex(
            self.settings,
            re.compile(r"case RootSectionActions:\s+return 4;"),
        )
        self.assertIn('cell.textLabel.text = @"Check for Updates";', self.settings)
        self.assertIn(
            "settings_run_hail_mary_app_library_miniature_refresh_action(void)",
            self.settings,
        )

    def test_action_seeds_exact_targets_and_promises_no_lifecycle_mutation(self):
        action = function_slice(
            self.settings,
            "settings_run_hail_mary_app_library_miniature_refresh_action(void)",
            "static NSString *settings_icon_redirect_target_name(void)",
        )
        self.assertIn("reconcilePresentationLifecycle", action)
        self.assertIn('presentation[@"activeBundleIdentifiers"]', action)
        self.assertIn("No Objective-C method mutation", action)
        self.assertIn('@"objectiveCMethodMutations": @0', action)
        self.assertIn('@"processLifecycleMutations": @0', action)
        self.assertIn('@"sharedCacheWrites": @0', action)
        self.assertNotIn("SIGKILL", action)


if __name__ == "__main__":
    unittest.main()
