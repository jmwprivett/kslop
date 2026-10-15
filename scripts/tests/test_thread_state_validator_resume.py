import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "scripts/lab"
sys.path.insert(0, str(LAB))
SPEC = importlib.util.spec_from_file_location(
    "cnd_thread_state_validator_resume",
    LAB / "cnd_thread_state_validator_resume.py",
)
validator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(validator)


def event(stage: str, pc: int) -> dict:
    result = {
        "stage": stage,
        "pc": f"{pc:#018x}",
        "savedState": "0xfffffe2faa4c9e80",
        "statePC": "0x0000000100014000",
        "stateCPSR": "0x00000000",
        "stateLR": "0x0000000100014004",
        "stateX16": f"{validator.MARKER_X16:#018x}",
        "stateX17": f"{validator.MARKER_X17:#018x}",
        "jopHash": "0xb451aaa400000000",
        "currentPSTATE": "0x204003c5",
        "irqMasked": True,
        "spsel": 1,
    }
    return result


class ThreadStateValidatorResumeTests(unittest.TestCase):
    def test_probe_source_has_bounded_gate_and_exact_markers(self) -> None:
        source = (LAB /
                  "cnd_thread_state_pac_exception_identity_probe.c").read_text(
                      encoding="utf-8")
        self.assertIn("--debug-gate", source)
        self.assertIn("poll(&gate, 1, 20000)", source)
        self.assertIn("0x434e4456414c3136ULL", source)
        self.assertIn("0x434e4456414c3137ULL", source)
        self.assertIn("validator_markers_restored", source)

    def test_lldb_plan_uses_exact_converter_callsite_and_detaches(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(validator, "BUILD_DIR", Path(directory)):
            command = validator.lldb_command_file(
                62139, 0xFFFFFE0045669DD4, 0xFFFFFE00454C5394,
                0xFFFFFE0045669DD8, validator.MARKER_X17,
                0xFFFFFE2FAA4C9E80,
                Path(directory) / "events.jsonl")
            text = command.read_text(encoding="utf-8")
        self.assertIn("gdb-remote 127.0.0.1:62139", text)
        self.assertIn("lldb.debugger.SetAsync(False)", text)
        self.assertIn("cnd_validator_bp.install", text)
        self.assertIn(str(0xFFFFFE2FAA4C9E80), text)
        self.assertEqual(text.count("capture_targeted"), 1)
        self.assertIn("process detach", text)

    def test_event_validation_requires_entry_and_return_on_same_state(self) -> None:
        validator_address = 0xFFFFFE00454C5394
        pre_address = 0xFFFFFE0045669DD4
        after_address = 0xFFFFFE0045669DD8
        saved_state = 0xFFFFFE2FAA4C9E80
        events = [
            event("pre-validator", pre_address),
            event("validator", validator_address),
            event("after-check", after_address),
        ]
        probe = {
            "raw_resume_pc": "0x0000000100014000",
            "raw_fallback_lr": "0x0000000100014004",
        }
        validator.validate_events(
            events, pre_address, validator_address, after_address,
            validator.MARKER_X17, saved_state, probe)
        events[2]["savedState"] = "0xfffffe2faa4c9d00"
        with self.assertRaisesRegex(validator.LabError, "retain"):
            validator.validate_events(
                events, pre_address, validator_address, after_address,
                validator.MARKER_X17, saved_state, probe)

    def test_ready_marker_and_saved_state_resolution_are_exact(self) -> None:
        pid, port, marker_x17 = validator.parse_ready_marker(
            b"CND_VALIDATOR_READY pid=417 thread_port=0x1603 "
            b"x17=0x0000000000000000\n")
        self.assertEqual((pid, port, marker_x17), (417, 0x1603, 0))
        ssh = mock.Mock()
        ssh.command.return_value = json.dumps({
            "schema": "com.zeroxjf.cyanide.thread-saved-state-resolve",
            "kernelBase": "0xfffffe0044a10000",
            "pid": pid,
            "portName": "0x1603",
            "contextData": "0xfffffe2faa4c9e80",
            "savedState": "0xfffffe2faa4c9e80",
            "uNeon": "0xfffffe2faa4c9fb0",
            "layoutExact": True,
            "x16Address": "0xfffffe2faa4c9f08",
            "x17Address": "0xfffffe2faa4c9f10",
            "pcAddress": "0xfffffe2faa4c9f88",
            "jopHashAddress": "0xfffffe2faa4c9fa8",
            "usedKernelRead": True,
            "usedKernelWrite": False,
            "usedKernelCall": False,
        })
        report = validator.resolve_saved_state(
            ssh, "/var/tmp/resolver", 0xFFFFFE0044A10000,
            0x3DA0C000, pid, port)
        self.assertEqual(report["savedState"], "0xfffffe2faa4c9e80")
        self.assertIn(" 417 0x1603", ssh.command.call_args.args[0])

    def test_probe_markers_are_exact_and_debug_gated(self) -> None:
        probe = {
            "debug_gate_used": True,
            "validator_gate_used": True,
            "retained_x17": True,
            "validator_markers_restored": True,
            "validator_marker_x16": f"{validator.MARKER_X16:#018x}",
            "validator_marker_x17": f"{validator.MARKER_X17:#018x}",
            "resumed_x16": f"{validator.MARKER_X16:#018x}",
            "resumed_x17": f"{validator.MARKER_X17:#018x}",
        }
        validator.validate_probe_markers(probe, validator.MARKER_X17)
        probe["debug_gate_used"] = False
        with self.assertRaisesRegex(validator.LabError, "exact markers"):
            validator.validate_probe_markers(probe, validator.MARKER_X17)

    def test_live_instruction_reader_is_read_only_and_exact(self) -> None:
        words = validator.EXPECTED_VALIDATOR_WORDS
        payload = b"".join(word.to_bytes(4, "little") for word in words)
        ssh = mock.Mock()
        ssh.command.return_value = json.dumps({
            "operation": "read",
            "bytes": payload.hex(),
            "usedKernelWrite": False,
            "usedKernelCall": False,
        })
        report = validator.read_kernel_words(
            ssh, "/var/tmp/reader", 0xFFFFFE0044A10000,
            0xFFFFFE00454C5394, words, "validator")
        self.assertTrue(report["exact"])
        self.assertIn(" read ", ssh.command.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
