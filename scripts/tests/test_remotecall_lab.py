"""Offline tests for the fail-closed vPhone RemoteCall repair gate."""

from __future__ import annotations

import importlib.util
import struct
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "lab/cnd_remotecall_lab.py"
SPEC = importlib.util.spec_from_file_location("cnd_remotecall_lab", MODULE_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class MarkerTests(unittest.TestCase):
    def test_parse_marker_rejects_duplicate_key(self) -> None:
        with self.assertRaisesRegex(lab.LabError, "invalid marker line"):
            lab.parse_marker("target=SpringBoard\ntarget=Spotlight\n")

    def test_validate_marker_binds_target_pid_and_socket(self) -> None:
        values = lab.parse_marker(
            "version=1\nmodel=VPHONE\ntarget=SpringBoard\npid=39\n"
            "socket=/var/tmp/cyanide-remotecall-SpringBoard.sock\n"
        )
        self.assertEqual(
            lab.validate_target_marker(values, "SpringBoard", 39),
            "/var/tmp/cyanide-remotecall-SpringBoard.sock",
        )
        with self.assertRaisesRegex(lab.LabError, "PID is stale"):
            lab.validate_target_marker(values, "SpringBoard", 40)
        with self.assertRaisesRegex(lab.LabError, "wrong target"):
            lab.validate_target_marker(values, "Spotlight", 39)


class MailboxTests(unittest.TestCase):
    def test_mailbox_sequences_require_exact_protocol_size(self) -> None:
        data = bytearray(lab.MAILBOX_SIZE)
        struct.pack_into("<QQ", data, 0, 202, 201)
        self.assertEqual(lab.mailbox_sequences(bytes(data)), (202, 201))
        with self.assertRaisesRegex(lab.LabError, "size mismatch"):
            lab.mailbox_sequences(bytes(data[:-1]))

    def test_expected_endpoint_is_target_specific(self) -> None:
        self.assertEqual(
            lab.expected_socket_path("SpringBoard"),
            "/var/tmp/cyanide-remotecall-SpringBoard.sock",
        )
        self.assertEqual(
            lab.expected_socket_path("installd"),
            "/var/installd/Library/Caches/.cnd-rc",
        )


if __name__ == "__main__":
    unittest.main()
