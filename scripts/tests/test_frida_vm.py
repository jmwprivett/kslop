import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "scripts/lab"
sys.path.insert(0, str(LAB))
SPEC = importlib.util.spec_from_file_location(
    "cnd_frida_vm", LAB / "cnd_frida_vm.py")
frida_vm = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(frida_vm)


class FridaVMTests(unittest.TestCase):
    def test_release_lock_is_exact_and_official(self) -> None:
        self.assertRegex(frida_vm.FRIDA_VERSION, r"^\d+\.\d+\.\d+$")
        self.assertRegex(frida_vm.FRIDA_TOOLS_VERSION, r"^\d+\.\d+\.\d+$")
        self.assertEqual(len(frida_vm.PACKAGE_SHA256), 64)
        self.assertTrue(frida_vm.PACKAGE_URL.startswith(
            "https://github.com/frida/frida/releases/download/"))
        self.assertIn(frida_vm.FRIDA_VERSION, frida_vm.PACKAGE_URL)

    def test_verified_package_rejects_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "frida.deb"
            path.write_bytes(b"not the locked package")
            self.assertFalse(frida_vm.verified_package(path))

    def test_expected_server_is_loopback_only_and_exact(self) -> None:
        expected = "frida-server -D -l 127.0.0.1:27042"
        self.assertTrue(frida_vm.expected_server_process(expected))
        self.assertFalse(frida_vm.expected_server_process(
            "frida-server -D -l 0.0.0.0:27042"))
        self.assertFalse(frida_vm.expected_server_process(
            "frida-server -D -l 127.0.0.1:27043"))

    def test_server_process_parser_requires_valid_pid(self) -> None:
        ssh = mock.Mock()
        ssh.command.return_value = (
            " 849 frida-server -D -l 127.0.0.1:27042\n")
        self.assertEqual(
            frida_vm.server_processes(ssh),
            [(849, "frida-server -D -l 127.0.0.1:27042")],
        )
        ssh.command.return_value = "not-a-pid frida-server\n"
        with self.assertRaisesRegex(frida_vm.LabError, "malformed"):
            frida_vm.server_processes(ssh)

    def test_tunnel_arguments_bind_only_host_loopback(self) -> None:
        with mock.patch.object(frida_vm.shutil, "which", return_value="/sshpass"), \
                mock.patch.dict(frida_vm.os.environ,
                                {"CND_VPHONE_ROOT_PASSWORD": "test"}):
            command, environment = frida_vm.tunnel_base(
                "192.168.64.116", 22222, "root", Path("/known_hosts"),
                "CND_VPHONE_ROOT_PASSWORD")
        self.assertEqual(environment["SSHPASS"], "test")
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertNotIn("test", command)
        self.assertEqual(frida_vm.LOCAL_ENDPOINT, "127.0.0.1:27042")
        self.assertEqual(frida_vm.REMOTE_LISTEN, "127.0.0.1:27042")

    def test_cli_defaults_to_privileged_vphone_endpoint(self) -> None:
        args = frida_vm.parser().parse_args([
            "setup", "--host", "192.168.64.116"])
        self.assertEqual(args.port, 22222)
        self.assertEqual(args.user, "root")
        self.assertEqual(args.password_env, "CND_VPHONE_ROOT_PASSWORD")

    def test_smoke_agent_is_observation_only(self) -> None:
        source = (LAB / "cnd_frida_springboard_smoke.py").read_text(
            encoding="utf-8")
        self.assertIn("Process.enumerateModules()", source)
        self.assertIn('"writesPerformed": False', source)
        self.assertIn('"hooksInstalled": False', source)
        self.assertNotIn("Interceptor.attach", source)
        self.assertNotIn("Memory.write", source)
        self.assertNotIn("NativeFunction", source)


if __name__ == "__main__":
    unittest.main()
