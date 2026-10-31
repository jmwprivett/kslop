"""Gravity cleanup must not add remote window walks to an unrelated Run."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def body(source: str, signature: str) -> str:
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]


class GravityLiteCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.settings = (ROOT / "Cyanide/SettingsViewController.m").read_text()
        cls.gravity = (ROOT / "Cyanide/tweaks/gravitylite.m").read_text()

    def test_sbc_only_run_has_no_direct_gravity_remote_stop(self) -> None:
        run = body(self.settings, "static void settings_run_actions_internal(")
        self.assertNotIn("gravitylite_stop_in_session()", run)
        self.assertNotIn("gravitylite_restore_in_session()", run)
        self.assertIn("settings_request_gravitylite_stop();", run)
        self.assertLess(run.index("settings_stop_disabled_applied_springboard_tweaks_locked(d)"),
                        run.index("if (runSBC) {"))

    def test_apply_owns_one_stop_before_creating_new_state(self) -> None:
        apply = body(self.gravity, "bool gravitylite_apply_in_session(")
        self.assertEqual(apply.count("gravitylite_stop_in_session()"), 1)
        self.assertNotIn("gravitylite_restore_in_session()", apply)
        self.assertLess(apply.index("gravitylite_stop_in_session()"),
                        apply.index('gl_new_remote("NSMutableDictionary")'))

    def test_disabled_applied_cleanup_keeps_its_gate_and_recovery(self) -> None:
        needed = body(self.settings, "static BOOL settings_disabled_applied_springboard_cleanup_needed(")
        self.assertIn("![d boolForKey:entry->key] && settings_tweak_is_applied(entry->key)", needed)
        cleanup = body(self.settings, "static void settings_stop_disabled_applied_springboard_tweaks_locked(")
        self.assertLess(cleanup.index("[d boolForKey:entry->key] || !settings_tweak_is_applied(entry->key)"),
                        cleanup.index("entry->stop(NO)"))
        self.assertIn("settings_mark_tweak_applied(entry->key, NO)", cleanup)
        registered = body(self.settings, "static bool settings_stop_gravitylite_registered(")
        self.assertIn("settings_request_gravitylite_stop()", registered)
        self.assertIn("gravitylite_restore_in_session()", registered)
        self.assertIn('kSettingsGravityLiteEnabled, "Gravity Lite", settings_request_gravitylite_stop, settings_stop_gravitylite_registered',
                      self.settings)

    def test_manual_restore_and_live_disable_keep_orphan_recovery(self) -> None:
        action = body(self.settings, "- (void)runGravityLiteAction:")
        self.assertEqual(action.count("? gravitylite_restore_in_session()"), 2)
        start = self.settings.index("    if (settings_key_is_gravitylite(key)) {")
        end = self.settings.index("    if (settings_key_is_axonlite(key)) {", start)
        toggle = self.settings[start:end]
        self.assertIn("if (g_springboard_rc_ready) gravitylite_restore_in_session();", toggle)

    def test_orphan_recovery_does_not_enumerate_remote_subviews(self) -> None:
        cleanup = body(self.gravity, "static int gl_cleanup_gravity_overlays_in_window(")
        self.assertIn('"viewWithTag:"', cleanup)
        self.assertNotIn("gl_subviews", cleanup)
        self.assertNotIn("gl_array_object", cleanup)
        self.assertIn("attempt < 16", cleanup)
        self.assertIn("view == previous", cleanup)
        windows = body(self.gravity, "static int gl_cleanup_gravity_overlays_in_app_windows(")
        self.assertIn("if (count > 64) count = 64;", windows)

    @unittest.skipUnless(shutil.which("clang"), "requires clang")
    def test_production_stop_and_cleanup_have_bounded_remote_work(self) -> None:
        production = "\n".join(body(self.gravity, signature) for signature in (
            "static int gl_cleanup_gravity_overlays_in_window(",
            "static bool gl_stop_in_session(",
            "bool gravitylite_stop_in_session(",
            "bool gravitylite_restore_in_session(",
        ))
        with tempfile.TemporaryDirectory(prefix="cyanide-gravity-cleanup-") as directory:
            fixture = Path(directory) / "cleanup.c"
            executable = Path(directory) / "cleanup"
            fixture.write_text(HARNESS.replace("// PRODUCTION", production))
            compiled = subprocess.run(
                ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", str(fixture), "-o", str(executable)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
            self.assertEqual(executed.returncode, 0, executed.stderr)


HARNESS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint64_t kGravityLiteOverlayTag = 0x47524156ULL;
static uint64_t s_gravity_ptrs[8];
static int s_gravity_ptr_count;
static uint64_t state;
static int sweeps, lookups, removals, cursor, viewCount;
static bool failRemoval;
static uint64_t views[128];

static bool r_is_objc_ptr(uint64_t value) { return value != 0; }
static bool r_responds_main(uint64_t value, const char *selector) {
    assert(value == 1000 && !strcmp(selector, "viewWithTag:"));
    return true;
}
static uint64_t r_msg2_main(uint64_t object, const char *selector,
                            uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    assert(!b && !c && !d);
    if (!strcmp(selector, "viewWithTag:")) {
        assert(object == 1000 && a == kGravityLiteOverlayTag);
        lookups++;
        return cursor < viewCount ? views[cursor] : 0;
    }
    assert(!strcmp(selector, "removeFromSuperview") && object == views[cursor] && !a);
    removals++;
    if (!failRemoval) cursor++;
    return 0;
}
static uint64_t gl_icon_controller(void) { return 100; }
static uint64_t gl_get_state(uint64_t controller) { assert(controller == 100); return state; }
static void gl_set_state(uint64_t controller, uint64_t value) { assert(controller == 100); state = value; }
static int gl_cleanup_gravity_overlays_in_app_windows(void) { sweeps++; return 0; }
static uint64_t gl_dict_get(uint64_t object, const char *key) { (void)object; (void)key; return 0; }
static uint64_t gl_array_count(uint64_t array) { (void)array; return 0; }
static uint64_t gl_array_object(uint64_t array, uint64_t index) { (void)array; (void)index; return 0; }
static void gl_reset_transform(uint64_t item) { (void)item; }
static int gl_restore_live_items(uint64_t items, uint64_t parents, uint64_t frames) {
    (void)items; (void)parents; (void)frames; return 0;
}
static int gl_unhide_icon_array(uint64_t array) { (void)array; return 0; }
static void gl_set_array_views_alpha(uint64_t array, double alpha) { (void)array; (void)alpha; }
static void gl_set_double(uint64_t object, const char *selector, double value) {
    (void)object; (void)selector; (void)value;
}
static void gl_layout_list_view(uint64_t view) { (void)view; }

// PRODUCTION

static void reset(int count, bool fail) {
    viewCount = count;
    failRemoval = fail;
    cursor = lookups = removals = 0;
    for (int i = 0; i < 128; i++) views[i] = 2000 + i;
}

int main(void) {
    // No associated state: ordinary stop must perform no orphan search.
    state = 0;
    s_gravity_ptr_count = 1;
    s_gravity_ptrs[0] = 123;
    assert(gravitylite_stop_in_session());
    assert(!sweeps && !lookups && !removals);
    assert(!s_gravity_ptr_count && !s_gravity_ptrs[0]);
    assert(gravitylite_restore_in_session());
    assert(sweeps == 1);
    // An ordinary active-state stop still clears state and sweeps leftovers.
    state = 999;
    assert(gravitylite_stop_in_session());
    assert(!state && sweeps == 2);

    reset(0, false);
    assert(gl_cleanup_gravity_overlays_in_window(1000) == 0);
    assert(lookups == 1 && removals == 0);
    reset(3, false);
    assert(gl_cleanup_gravity_overlays_in_window(1000) == 3);
    assert(lookups == 4 && removals == 3);
    reset(128, false);
    assert(gl_cleanup_gravity_overlays_in_window(1000) == 16);
    assert(lookups == 16 && removals == 16);
    reset(3, true);
    assert(gl_cleanup_gravity_overlays_in_window(1000) == 1);
    assert(lookups == 2 && removals == 1);
    reset(1, false);
    views[0] = 1000;
    assert(gl_cleanup_gravity_overlays_in_window(1000) == 0);
    assert(removals == 0);
    assert(gl_cleanup_gravity_overlays_in_window(0) == 0);
    return 0;
}
'''


if __name__ == "__main__":
    unittest.main()
