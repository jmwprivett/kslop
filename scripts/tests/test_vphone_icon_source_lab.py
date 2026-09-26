"""Offline safety tests for vphone_icon_source_lab.py.

The fixtures are ordinary host files and a fake/local transport. No test
contacts a VM, invokes build.sh, or modifies the checked-in theme archive.
"""

from __future__ import annotations

import json
import plistlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vphone_icon_source_lab as lab  # noqa: E402


class Phase6HarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.vm_bundle = self.base / "vphone.bundle"
        self.vm_bundle.mkdir()
        for filename in (lab.EXPECTED_DISK_IMAGE, lab.EXPECTED_NVRAM_STORAGE, lab.EXPECTED_SEP_STORAGE):
            (self.vm_bundle / filename).write_bytes(b"fixture")
        self.identity = lab.EXPECTED_IDENTITY.as_dict()
        self.vm_config = self.vm_bundle / "config.plist"
        self.vm_config.write_bytes(plistlib.dumps({
            "platformType": lab.EXPECTED_PLATFORM_TYPE,
            "machineIdentifier": plistlib.dumps({"ECID": lab.EXPECTED_ECID}, fmt=plistlib.FMT_BINARY),
            "diskImage": lab.EXPECTED_DISK_IMAGE,
            "nvramStorage": lab.EXPECTED_NVRAM_STORAGE,
            "sepStorage": lab.EXPECTED_SEP_STORAGE,
        }))
        self.theme = self.base / "theme.zip"
        with zipfile.ZipFile(self.theme, "w") as archive:
            archive.writestr(lab.DEFAULT_THEME_ENTRY, b"theme replacement")
        self.ipa = self.base / lab.DEFAULT_DIAGNOSTIC_IPA.name
        with zipfile.ZipFile(self.ipa, "w") as archive:
            archive.writestr("Payload/Cyanide.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": lab.EXPECTED_BUNDLE_ID}))
        self.remote_root = self.base / "guest"
        self.remote_root.mkdir()
        self.target = self.remote_root / "canonical.png"
        self.target.write_bytes(b"original bytes")
        self.replacement = self.base / "staged.png"
        self.replacement.write_bytes(b"replacement bytes")
        self.app = self.base / "installed.app"
        self.app.mkdir()
        (self.app / "Info.plist").write_bytes(b"app backup")
        nested = self.app / "Base.lproj" / "Main.storyboardc"
        nested.mkdir(parents=True)
        (nested / "Info.plist").write_bytes(b"nested backup")
        self.backup = self.base / "backup"
        lab.create_app_backup(self.app, self.backup)
        self.checkpoint = self.base / "checkpoint"
        self.checkpoint.mkdir()
        (self.checkpoint / "checkpoint.json").write_text(json.dumps({
            "verified": True, "cold": True, "vm_stopped": True,
            "disk_open": False, "identity_preserved": True,
            "identity": self.identity,
        }), encoding="utf-8")
        original_metadata = lab.metadata(self.target)
        # Some macOS Python builds omit the xattr bindings. The fixture has
        # an explicitly empty xattr set, so mark that fact for local tests.
        original_metadata["xattrs_supported"] = True
        self.manifest = {
            "schema": 1,
            "run_id": "offline-test",
            "identity": self.identity,
            "resolved_arm": {"kind": "png", "resolved_path": str(self.target)},
            "allowlisted_mapping": [{
                "target": str(self.target), "replacement": str(self.replacement),
                "original_sha256": lab.sha256_file(self.target),
                "replacement_sha256": lab.sha256_file(self.replacement),
                "original_metadata": original_metadata,
            }],
            "recovery_command": ["manual", "phase6-restore"],
            "manual_invalidation_acknowledged": True,
        }
        self.root = self.base / "run"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def prepare_run(self) -> None:
        # The implementation is macOS-host-only; test environments may run
        # elsewhere, so this test explicitly exercises the same host branch.
        with mock.patch.object(lab.sys, "platform", "darwin"):
            lab.prepare(
                run_root=self.root, manifest=self.manifest,
                vm_bundle=self.vm_bundle, vm_config=self.vm_config,
                identity=self.identity, theme_archive=self.theme,
                diagnostic_ipa=self.ipa, checkpoint=self.checkpoint,
                app_backup=self.backup,
            )

    def test_preflight_is_read_only_and_pins_identity(self) -> None:
        before = sorted(self.base.rglob("*"))
        with mock.patch.object(lab.sys, "platform", "darwin"):
            report = lab.preflight(vm_bundle=self.vm_bundle, vm_config=self.vm_config,
                                   identity=self.identity, theme_archive=self.theme,
                                   diagnostic_ipa=self.ipa, checkpoint=self.checkpoint,
                                   app_backup=self.backup)
        self.assertTrue(report["ok"])
        self.assertEqual(before, sorted(self.base.rglob("*")))
        with self.assertRaises(lab.RefusalError):
            bad = dict(self.identity, udid="wrong")
            lab.validate_guest_identity(bad)

    def test_embedded_ecid_manifest_fields_are_required_without_udid_text(self) -> None:
        config_bytes = self.vm_config.read_bytes()
        self.assertNotIn(self.identity["udid"].encode(), config_bytes)
        with mock.patch.object(lab.sys, "platform", "darwin"):
            report = lab.validate_vm_bundle_and_config(self.vm_bundle, self.vm_config, self.identity)
        self.assertEqual(report["vm_manifest"]["machine_ecid"], lab.EXPECTED_ECID)
        wrong = plistlib.loads(config_bytes)
        wrong["machineIdentifier"] = plistlib.dumps({"ECID": lab.EXPECTED_ECID - 1}, fmt=plistlib.FMT_BINARY)
        self.vm_config.write_bytes(plistlib.dumps(wrong))
        with self.assertRaises(lab.RefusalError):
            lab.validate_vm_bundle_and_config(self.vm_bundle, self.vm_config, self.identity)

    def test_vm_bundle_is_pinned_structurally_not_by_its_name(self) -> None:
        renamed_bundle = self.base / "cyanide-ios26-base"
        self.vm_bundle.rename(renamed_bundle)
        renamed_config = renamed_bundle / "config.plist"
        report = lab.validate_vm_bundle_and_config(renamed_bundle, renamed_config, self.identity)
        self.assertEqual(report["vm_manifest"]["machine_ecid"], lab.EXPECTED_ECID)

        outside_config = self.base / "config.plist"
        outside_config.write_bytes(renamed_config.read_bytes())
        with self.assertRaises(lab.RefusalError):
            lab.validate_vm_bundle_and_config(renamed_bundle, outside_config, self.identity)

    def test_ssh_uses_jb_tools_and_guest_system_version_plist(self) -> None:
        class FakeSSH(lab.SSHTransport):
            def __init__(self, identity: dict[str, object]) -> None:
                super().__init__("vphone.example", guest_identity=identity)
                self.commands: list[list[str]] = []

            def _ssh(self, command: list[str] | tuple[str, ...], *, input_data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
                command_list = list(command)
                self.commands.append(command_list)
                tool = command_list[0]
                if len(command_list) == 2 and command_list[1] == "--version":
                    # Only the observed /var/jb tools are available. This
                    # makes accidental /usr/bin assumptions fail loudly.
                    available = tuple(lab.REMOTE_TOOL_CANDIDATES.values())
                    if tool in {candidate for candidates in available for candidate in candidates if candidate.startswith("/var/jb/")}:  # noqa: SIM118
                        return subprocess.CompletedProcess(command_list, 0, b"GNU coreutils 9.5\n", b"")
                    return subprocess.CompletedProcess(command_list, 127, b"", b"not found")
                if tool.endswith("/cat"):
                    data = plistlib.dumps({"ProductVersion": "26.0", "ProductBuildVersion": "23A341"})
                    return subprocess.CompletedProcess(command_list, 0, data, b"")
                if tool.endswith("/realpath"):
                    return subprocess.CompletedProcess(command_list, 0, command_list[-1].encode() + b"\n", b"")
                if tool.endswith("/stat"):
                    return subprocess.CompletedProcess(command_list, 0, b"8124|444|0|0|571|1757401474|1757401474|2025-09-08 11:24:34.123456789 -0700|2025-09-08 11:24:34.987654321 -0700\n", b"")
                if tool.endswith("/sha256sum"):
                    return subprocess.CompletedProcess(command_list, 0, ("a" * 64 + "  /target\n").encode(), b"")
                if tool.endswith("/xattr"):
                    return subprocess.CompletedProcess(command_list, 0, b"", b"")
                return subprocess.CompletedProcess(command_list, 0, b"", b"")

        fake = FakeSSH(self.identity)
        self.assertEqual(fake.identity()["ios_version"], "26.0")
        self.assertEqual(fake.resolve("/target"), "/target")
        remote_stat = fake.stat("/target")
        self.assertEqual(remote_stat["mode"], 0o444)
        self.assertEqual(remote_stat["atime_ns"], 1757401474123456789)
        self.assertEqual(remote_stat["mtime_ns"], 1757401474987654321)
        self.assertTrue(remote_stat["xattrs_supported"])
        self.assertEqual(remote_stat["flags_preservation"], "opaque-cp-preserve-all")
        self.assertTrue(all(not command[0].startswith("/usr/bin/") for command in fake.commands))

    def test_ssh_quotes_each_remote_argument(self) -> None:
        transport = lab.SSHTransport("vphone.example", guest_identity=self.identity)
        with mock.patch.object(lab.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
            transport._ssh(["/var/jb/usr/bin/stat", "-c", "%f %a", "/a path"])
        remote_command = run.call_args.args[0][-1]
        self.assertEqual(remote_command, "/var/jb/usr/bin/stat -c '%f %a' '/a path'")

    def test_ssh_write_refuses_unverified_xattrs_and_restores_metadata_after_tee(self) -> None:
        class RecordingSSH(lab.SSHTransport):
            def __init__(self) -> None:
                super().__init__("vphone.example", guest_identity=lab.EXPECTED_IDENTITY.as_dict(), execute=True)
                self.commands: list[list[str]] = []

            def _ssh(self, command: list[str] | tuple[str, ...], *, input_data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
                command_list = list(command)
                self.commands.append(command_list)
                if len(command_list) == 2 and command_list[1] == "--version":
                    return subprocess.CompletedProcess(command_list, 0, b"GNU coreutils 9.5\n", b"")
                return subprocess.CompletedProcess(command_list, 0, b"", b"")

        fake = RecordingSSH()
        with self.assertRaises(lab.RefusalError):
            fake.write_temp("/target", b"new", {"xattrs_supported": False, "flags_supported": False}, "run")
        fake.write_temp("/target", b"new", {"xattrs_supported": True, "flags_supported": True}, "run")
        tee_indexes = [i for i, command in enumerate(fake.commands) if command[0].endswith("/tee") and len(command) > 2]
        self.assertEqual(len(tee_indexes), 1)
        self.assertTrue(any("--attributes-only" in command for command in fake.commands[tee_indexes[0] + 1:]))

    def test_archive_traversal_duplicate_and_protected_ipa_refuse(self) -> None:
        traversal = self.base / "traversal.zip"
        with zipfile.ZipFile(traversal, "w") as archive:
            archive.writestr("../evil", b"x")
        with self.assertRaises(lab.RefusalError):
            lab.validate_theme_archive(traversal, "../evil")
        duplicate = self.base / "duplicate.zip"
        with zipfile.ZipFile(duplicate, "w") as archive:
            archive.writestr(lab.DEFAULT_THEME_ENTRY, b"one")
            archive.writestr(lab.DEFAULT_THEME_ENTRY, b"two")
        with self.assertRaises(lab.RefusalError):
            lab.validate_theme_archive(duplicate)
        with self.assertRaises(lab.RefusalError):
            lab.validate_diagnostic_ipa(self.base / "Cyanide.ipa")

    def test_ambiguous_manifest_and_unverified_checkpoint_refuse(self) -> None:
        with self.assertRaises(lab.RefusalError):
            lab.validate_prepared_manifest(dict(self.manifest, resolved_arm={"kind": "unknown", "path": str(self.target)}))
        bad = self.checkpoint / "checkpoint.json"
        bad.write_text(json.dumps({"verified": False}), encoding="utf-8")
        with self.assertRaises(lab.RefusalError):
            lab.validate_cold_checkpoint(self.checkpoint, self.identity)

    def test_status_apply_restore_verify_and_idempotence(self) -> None:
        self.prepare_run()
        transport = lab.LocalTransport(self.identity, root=self.remote_root, execute=True)
        applied = lab.apply(run_root=self.root, transport=transport, execute=True, confirmation=lab.CONFIRM_TOKEN)
        self.assertEqual(applied["state"], "applied")
        self.assertEqual(transport.read_bytes(str(self.target)), self.replacement.read_bytes())
        evidence = self.base / "operator-evidence.txt"
        evidence.write_text("operator performed equivalent invalidation gates\n", encoding="utf-8")
        restored = lab.restore(run_root=self.root, transport=transport, execute=True,
                               confirmation=lab.CONFIRM_TOKEN, operator_evidence=evidence)
        self.assertEqual(restored["state"], "restored")
        self.assertEqual(transport.read_bytes(str(self.target)), b"original bytes")
        self.assertEqual(lab.restore(run_root=self.root, transport=transport,
                                     execute=True, confirmation=lab.CONFIRM_TOKEN)["state"], "restored")
        verified = lab.verify_restored(run_root=self.root, transport=transport)
        self.assertEqual(verified["state"], "verified-restored")

    def test_changed_original_is_refused_without_write(self) -> None:
        self.prepare_run()
        self.target.write_bytes(b"unexpected mutation")
        transport = lab.LocalTransport(self.identity, root=self.remote_root, execute=True)
        with self.assertRaises(lab.RefusalError):
            lab.apply(run_root=self.root, transport=transport, execute=True, confirmation=lab.CONFIRM_TOKEN)
        self.assertEqual(lab.status(run_root=self.root)["state"], "prepared")

    def test_interruption_is_rollback_required_and_temp_is_cleaned(self) -> None:
        self.prepare_run()

        class InterruptingTransport(lab.LocalTransport):
            interrupted = False

            def read_bytes(self, path: str) -> bytes:
                if ".phase6-" in path and not self.interrupted:
                    self.interrupted = True
                    raise KeyboardInterrupt("simulated readback interruption")
                return super().read_bytes(path)

        transport = InterruptingTransport(self.identity, root=self.remote_root, execute=True)
        with self.assertRaises(KeyboardInterrupt):
            lab.apply(run_root=self.root, transport=transport, execute=True, confirmation=lab.CONFIRM_TOKEN)
        self.assertEqual(lab.status(run_root=self.root)["state"], "rollback-required")
        evidence = self.base / "operator-evidence.txt"
        evidence.write_text("manual invalidation evidence", encoding="utf-8")
        restored = lab.restore(run_root=self.root, transport=lab.LocalTransport(self.identity, root=self.remote_root, execute=True), execute=True, confirmation=lab.CONFIRM_TOKEN, operator_evidence=evidence)
        self.assertEqual(restored["state"], "restored")
        self.assertFalse(any(path.name.endswith(".tmp") for path in self.remote_root.iterdir()))

    def test_newly_introduced_allowlisted_file_is_removed_on_restore(self) -> None:
        introduced = self.remote_root / "new-canonical.png"
        manifest = dict(self.manifest)
        manifest["allowlisted_mapping"] = [{
            "target": str(introduced), "replacement": str(self.replacement),
            "original_sha256": "0" * 64, "replacement_sha256": lab.sha256_file(self.replacement),
            "original_metadata": {"type": "missing"}, "original_exists": False,
            "replacement_metadata": {**lab.metadata(self.replacement), "xattrs_supported": True},
        }]
        with mock.patch.object(lab.sys, "platform", "darwin"):
            lab.prepare(run_root=self.root, manifest=manifest, vm_bundle=self.vm_bundle,
                        vm_config=self.vm_config, identity=self.identity,
                        theme_archive=self.theme, diagnostic_ipa=self.ipa,
                        checkpoint=self.checkpoint, app_backup=self.backup)
        transport = lab.LocalTransport(self.identity, root=self.remote_root, execute=True)
        lab.apply(run_root=self.root, transport=transport, execute=True, confirmation=lab.CONFIRM_TOKEN)
        self.assertTrue(introduced.exists())
        evidence = self.base / "operator-evidence.txt"
        evidence.write_text("manual invalidation evidence", encoding="utf-8")
        lab.restore(run_root=self.root, transport=transport, execute=True,
                    confirmation=lab.CONFIRM_TOKEN, operator_evidence=evidence)
        self.assertFalse(introduced.exists())


if __name__ == "__main__":
    unittest.main()
