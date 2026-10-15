import importlib.util
import io
import struct
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "scripts/lab"
sys.path.insert(0, str(LAB))
SPEC = importlib.util.spec_from_file_location(
    "cnd_frida_krw_bridge", LAB / "cnd_frida_krw_bridge.py")
bridge = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)


class FakeProcess:
    def __init__(self, response: bytes) -> None:
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(response)
        self.stderr = io.BytesIO()


class MemoryClient:
    def __init__(self, images: dict[int, bytes]) -> None:
        self.images = images

    def read(self, address: int, length: int) -> bytes:
        for base, data in self.images.items():
            if base <= address and address + length <= base + len(data):
                offset = address - base
                return data[offset:offset + length]
        raise AssertionError(f"unmapped test read {address:#x}+{length:#x}")


def macho_header(filetype: int, ncmds: int, sizeofcmds: int) -> bytes:
    return struct.pack(
        "<IiiIIIII", bridge.MH_MAGIC_64, 0x100000C, 2,
        filetype, ncmds, sizeofcmds, 0, 0,
    )


class FridaKRWBridgeTests(unittest.TestCase):
    def test_client_emits_only_read_protocol_frames(self) -> None:
        payload = b"ABCD"
        responses = b"".join((
            bridge.RESPONSE.pack(bridge.CND_MAGIC, 0, 0, 0, 0xF),
            bridge.RESPONSE.pack(
                bridge.CND_MAGIC, 0, len(payload), 0, 0),
            payload,
        ))
        process = FakeProcess(responses)
        client = bridge.ReadOnlyProvider(process)  # type: ignore[arg-type]
        self.assertEqual(client.capabilities(), 0xF)
        self.assertEqual(client.read(0xFFFFFE0044A10000, 4), payload)
        frames = process.stdin.getvalue()
        first = bridge.REQUEST.unpack(frames[:bridge.REQUEST.size])
        second = bridge.REQUEST.unpack(frames[bridge.REQUEST.size:])
        self.assertEqual(first[2], bridge.CND_OPERATION_CAPABILITIES)
        self.assertEqual(second[2], bridge.CND_OPERATION_READ)
        with self.assertRaisesRegex(bridge.LabError, "only permits read"):
            client._request(3, 0xFFFFFE0044A10000, 4)

    def test_region_parser_and_limits(self) -> None:
        relative = bridge.parse_region("kernel+0x80:0x20:object-field")
        self.assertEqual(relative.base_name, "kernel")
        self.assertEqual(relative.offset, 0x80)
        absolute = bridge.parse_region(
            "0xfffffe0044a14000:8:absolute-field")
        self.assertEqual(absolute.absolute, 0xFFFFFE0044A14000)
        with self.assertRaisesRegex(Exception, "region base"):
            bridge.parse_region("user+0x10:8:bad")
        with self.assertRaisesRegex(Exception, "region length"):
            bridge.parse_region("kbase:0x4001:too-large")

    def test_exact_fileset_and_inner_uuid_identity(self) -> None:
        static_base = 0xFFFFFE0007004000
        live_base = 0xFFFFFE0044A10000
        kernel_offset = 0x4000
        segment = struct.pack(
            "<II16sQQQQiiII", bridge.LC_SEGMENT_64, 72,
            b"__TEXT\0" + b"\0" * 9, static_base, 0x4000,
            0, 0x4000, 7, 5, 0, 0,
        )
        name = b"com.apple.kernel\0"
        fileset_size = 56
        fileset = struct.pack(
            "<IIQQII", bridge.LC_FILESET_ENTRY, fileset_size,
            static_base + kernel_offset, kernel_offset, 32, 0,
        ) + name + b"\0" * (fileset_size - 32 - len(name))
        outer_commands = segment + fileset
        outer = macho_header(
            bridge.MH_FILESET, 2, len(outer_commands)) + outer_commands

        expected_uuid = uuid.UUID(bridge.EXPECTED_KERNEL_UUID).bytes
        uuid_command = struct.pack(
            "<II16s", bridge.LC_UUID, 24, expected_uuid)
        inner = macho_header(bridge.MH_EXECUTE, 1, 24) + uuid_command
        client = MemoryClient({
            live_base: outer,
            live_base + kernel_offset: inner,
        })
        identity = bridge.kernel_identity(client, live_base)  # type: ignore[arg-type]
        self.assertEqual(identity["kernelUUID"], bridge.EXPECTED_KERNEL_UUID)
        self.assertEqual(
            identity["kernelText"], f"{live_base + kernel_offset:#018x}")
        self.assertEqual(identity["kernelFileOffset"], "0x4000")
        self.assertEqual(identity["loadCommandsMode"], "static")
        self.assertEqual(
            identity["slide"], f"{live_base - static_base:#018x}")

    def test_diff_marks_changes_as_candidates_not_confirmed_pac(self) -> None:
        request = bridge.parse_region("kernel:0x10:mutable-object")
        before = bytes.fromhex("01000000000000aa" "0200000000000000")
        after = bytes.fromhex("01000000000000bb" "0300000000000000")
        report = bridge.diff_region(
            request, 0xFFFFFE0044A14000, before, after)
        self.assertFalse(report["unchanged"])
        self.assertEqual(report["changedByteCount"], 2)
        self.assertEqual(len(report["changedAlignedWords"]), 2)
        self.assertIn(
            "possiblePACOrTaggedValue", report["changedAlignedWords"][0])
        self.assertNotIn("confirmedPAC", str(report))

    def test_agent_and_relay_are_observation_only(self) -> None:
        agent = (LAB / "cnd_frida_krw_agent.js").read_text(encoding="utf-8")
        self.assertIn("Process.enumerateModules()", agent)
        self.assertNotIn("Interceptor.", agent)
        self.assertNotIn("Memory.write", agent)
        self.assertNotIn("NativeFunction", agent)

        relay = (LAB / "cnd_frida_krw_read_relay.c").read_text(
            encoding="utf-8")
        self.assertIn("request_is_read_only", relay)
        self.assertNotIn("CNDLabKRWOperationWrite", relay)
        self.assertNotIn("CNDLabKRWOperationKernelCall", relay)
        self.assertIn("send_error(EPERM)", relay)

    def test_kcall_boundary_report_is_strictly_parsed(self) -> None:
        with mock.patch.object(bridge, "build_binary", return_value=Path("/p")), \
                mock.patch.object(
                    bridge, "copy_binary",
                    return_value="/var/tmp/cnd-lab-krw-probe-0123456789abcdef",
                ), mock.patch.object(
                    bridge, "run_kcall_smoke",
                    return_value=(
                        "ready capabilities=0xf kernelCall=available "
                        "smoke=passed gadget=0xfffffe0012345678 "
                        "result=0"
                    ),
                ):
            report = bridge.run_boundary_probe(mock.Mock(), "kcall-smoke")
        self.assertEqual(report["result"], "passed")
        self.assertFalse(report["persistentKernelMutation"])

    def test_pac_boundary_requires_binding_invariants(self) -> None:
        output = (
            '{"schema":"com.zeroxjf.cyanide.thread-state-signer-canary",'
            '"deterministic":true,"binds_state_address":true,'
            '"binds_mode_and_control_state":true,'
            '"validator_invoked":false,"persistent_mutation":false}'
        )
        with mock.patch.object(bridge, "build_binary", return_value=Path("/p")), \
                mock.patch.object(
                    bridge, "copy_binary",
                    return_value="/var/tmp/cnd-lab-krw-probe-0123456789abcdef",
                ), mock.patch.object(
                    bridge, "run_thread_state_signer_canary",
                    return_value=output,
                ):
            report = bridge.run_boundary_probe(
                mock.Mock(), "pac-signer-canary")
        self.assertEqual(report["result"], "passed")
        self.assertFalse(report["validatorInvoked"])
        self.assertFalse(report["persistentKernelMutation"])

    def test_validator_resume_boundary_requires_every_invariant(self) -> None:
        names = {
            "targetSavedStateResolvedByReadOnlyKRW",
            "converterValidatorCallSiteMatched",
            "validatorEnteredWithMarkedTuple",
            "validatorIRQMasked",
            "validatorSPSelOne",
            "validatorReturnedToExpectedContinuation",
            "sameSavedStateAtEntryAndReturn",
            "jopHashStableAcrossValidation",
            "childResumedWithMarkedRegisters",
        }
        live_report = {
            "schema": "com.zeroxjf.cyanide.thread-state-validator-resume",
            "classification": "VM-proved",
            "result": "marked-state-validated-and-resumed",
            "invariants": {name: True for name in names},
            "safety": {
                "usedKernelWrite": False,
                "usedKernelCall": False,
                "persistentKernelMutation": False,
            },
        }
        args = mock.Mock(
            host="192.168.64.116", port=22222, user="root",
            known_hosts=Path("/tmp/known-hosts"),
            password_env="CND_VPHONE_ROOT_PASSWORD",
            kernel_debug_port=62139,
        )
        with mock.patch.object(
                bridge, "run_validator_resume", return_value=live_report):
            report = bridge.run_boundary_probe(
                mock.Mock(), "validator-resume-canary", args)
        self.assertEqual(report["result"], "passed")
        self.assertTrue(report["validatorInvoked"])
        live_report["invariants"]["validatorSPSelOne"] = False
        with mock.patch.object(
                bridge, "run_validator_resume", return_value=live_report):
            with self.assertRaisesRegex(bridge.LabError, "invariants"):
                bridge.run_boundary_probe(
                    mock.Mock(), "validator-resume-canary", args)


if __name__ == "__main__":
    unittest.main()
