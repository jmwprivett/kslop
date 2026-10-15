"""Offline safety and build contracts for the vPhone recipe canary."""

from pathlib import Path
import importlib.util
import os
import shutil
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "scripts/lab"
sys.path.insert(0, str(LAB))
SPEC = importlib.util.spec_from_file_location(
    "cnd_cc_material_recipe_canary",
    LAB / "cnd_cc_material_recipe_canary.py",
)
assert SPEC and SPEC.loader
CANARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CANARY)


class CCMaterialRecipeVMCanaryTests(unittest.TestCase):
    def test_payload_is_exact_target_build_and_vm_bounded(self) -> None:
        source = CANARY.SOURCE.read_text(encoding="utf-8")
        self.assertIn(
            "/System/Library/PrivateFrameworks/CoreMaterial.framework/"
            "modulesBackground.materialrecipe",
            source,
        )
        self.assertIn('isEqualToString:@"23A341"', source)
        self.assertIn("CNDIsVPhone()", source)
        self.assertIn('strcmp(getprogname(), "Cyanide")', source)
        self.assertIn("CNDExpectedRecipeLength = 343", source)
        self.assertIn("CNDCCCompileBackgroundMaterialRecipe", source)
        self.assertIn("CNDCCMaterialRecipeSizingPolicyAllowCompactBackground", source)
        self.assertNotIn("kill(", source)
        self.assertNotIn("resolve_target", source)
        self.assertNotIn("system(", source)

    def test_apply_journals_before_one_exact_write_and_restore_is_guarded(self) -> None:
        source = CANARY.SOURCE.read_text(encoding="utf-8")
        apply = source.split("static void CNDApply", 1)[1].split(
            "static void CNDRestore", 1
        )[0]
        self.assertLess(apply.index('@"state"] = @"writing"'), apply.index("CNDWriteTarget("))
        self.assertIn('@"targetFileWrites"] unsignedIntegerValue] + 1', source)
        self.assertIn("CNDBytesAreKnownPartialWrite", apply)
        restore = source.split("static void CNDRestore", 1)[1]
        self.assertIn("matched neither the canary payload nor its stock backup", restore)
        self.assertIn("CNDPath(CNDBackupName)", restore)
        self.assertIn('@"state"] = @"restored"', restore)

    def test_host_run_uses_finally_restore_and_exact_process_checks(self) -> None:
        source = (LAB / "cnd_cc_material_recipe_canary.py").read_text(encoding="utf-8")
        run_body = source.split("def run_canary", 1)[1].split("def parse_args", 1)[0]
        self.assertIn("finally:", run_body)
        self.assertLess(
            run_body.index("finally:\n        dismiss_overlays()"),
            run_body.index("_, app_home, _ = launch_cyanide(ssh)"),
        )
        self.assertIn('trigger_app_action(ssh, "restore")', run_body)
        self.assertIn('resolve_target(ssh, "SpringBoard")', source)
        self.assertIn("current_cyanide(ssh)", source)
        self.assertIn("require_vphone(ssh)", source)
        self.assertIn('{"t": "tap", "x": 1218, "y": 1230}', source)

    def test_app_native_trigger_is_one_shot_and_nonce_bound(self) -> None:
        source = CANARY.SOURCE.read_text(encoding="utf-8")
        self.assertIn("CNDCCMaterialRecipeVMCanaryProcessPendingRequest", source)
        self.assertIn("CNDCCMaterialRecipeVMCanaryStart", source)
        self.assertIn('getenv("CFFIXED_USER_HOME")', source)
        self.assertIn('request[@"targetSandboxToken"]', source)
        self.assertIn('"sandbox_extension_consume"', source)
        self.assertNotIn("overwrite_system_file_exact_pwrite", source)
        self.assertIn("removeItemAtPath:requestPath", source)
        self.assertIn('@"requestNonce"', source)
        host = (LAB / "cnd_cc_material_recipe_canary.py").read_text(encoding="utf-8")
        self.assertIn('report.get("requestNonce") != nonce', host)
        self.assertIn("issue_file_extension(ssh, TARGET_PATH)", host)
        self.assertIn("app_canary_directory(app_home)", host)

    def test_app_native_namecache_redirect_is_build_locked_and_pins_vnodes(self) -> None:
        source = CANARY.SOURCE.read_text(encoding="utf-8")
        resolve = source.split(
            "static BOOL CNDResolveRedirectState", 1
        )[1].split("static BOOL CNDApplyNamecacheRedirect", 1)[0]
        redirect = source.split(
            "static BOOL CNDApplyNamecacheRedirect", 1
        )[1].split("static BOOL CNDRestoreNamecacheRedirect", 1)[0]
        self.assertIn("CNDVnodeVIDOffset23A341 = 0x74", source)
        self.assertIn("CNDNamecacheNCVIDOffset23A341 = 0x40", source)
        self.assertIn("off_vnode_v_nclinks_lh_first == 0x40", resolve)
        self.assertIn("off_namecache_nc_vp == 0x50", resolve)
        self.assertIn("originalNCVnode == targetVnode", resolve)
        self.assertIn("originalNCVID == targetVID", resolve)
        self.assertIn("targetVnode + off_vnode_v_usecount", redirect)
        self.assertIn("payloadVnode + off_vnode_v_usecount", redirect)
        self.assertIn("targetNamecache + off_namecache_nc_vp, payloadVnode", redirect)
        self.assertIn("targetNamecache + CNDNamecacheNCVIDOffset23A341", redirect)
        apply = source.split("static void CNDApply", 1)[1].split(
            "static void CNDRestore", 1
        )[0]
        self.assertIn('@"redirectKind"] = @"namecache-nc-vp"', apply)
        self.assertIn('journal[@"targetPinned"] = @YES', apply)
        self.assertIn('journal[@"sourcePinned"] = @YES', apply)

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("xcrun"),
                         "requires the iPhoneOS toolchain")
    def test_both_injected_actions_build(self) -> None:
        old_directory = CANARY.BUILD_DIRECTORY
        try:
            CANARY.BUILD_DIRECTORY = Path(os.environ.get("TMPDIR", "/tmp")) / (
                "cnd-cc-material-recipe-canary-build-test"
            )
            for action in ("apply", "restore"):
                artifact = CANARY.build(action, 2, "offline-build-token")
                self.assertTrue(artifact.is_file())
        finally:
            CANARY.BUILD_DIRECTORY = old_directory


if __name__ == "__main__":
    unittest.main()
