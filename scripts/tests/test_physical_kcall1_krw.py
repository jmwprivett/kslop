#!/usr/bin/env python3
"""Tests for the physical-device kcall1 port harness.

Mirrors the kcall1 test shape in test_iouserethernet_krw_trigger.py and
the physical-probe hygiene pins in test_physical_panic_signature_probe.py:
the port reuses the shared validator, gates the exact phone, fails
closed on every unresolved route gap and every unresolved producer
layout element, refuses a producer that disagrees with the derivation,
never touches the VM paths, and never references the VM syscall-439
backend. Nothing here contacts a device: every SSH is a scripted fake,
every build is patched out.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import json
import re
import sys
import types
import unittest
import unittest.mock  # noqa: F401  (used as unittest.mock.patch)
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab"))

MODULE_PATH = Path(__file__).resolve().parents[1] / \
    "lab/cnd_physical_kcall1_krw.py"
TRIGGER_M = Path(__file__).resolve().parents[2] / \
    "scripts/lab/cnd_iouserethernet_krw_trigger.m"
PROVIDER_C = Path(__file__).resolve().parents[2] / \
    "scripts/lab/cnd_provide_tfp0.c"
VM_TRIGGER_PY = Path(__file__).resolve().parents[2] / \
    "scripts/lab/cnd_iouserethernet_krw_trigger.py"
VM_TESTS_PY = Path(__file__).resolve().parent / \
    "test_iouserethernet_krw_trigger.py"

MODULE = importlib.import_module("cnd_physical_kcall1_krw")
LabError = MODULE.LabError


def _vm_kcall1_fixture() -> dict:
    """The VM suite's validated kcall1 report fixture, loaded by path."""
    spec = importlib.util.spec_from_file_location(
        "cnd_vm_trigger_tests", VM_TESTS_PY)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module._kcall1_report()


def phone_kcall1_report() -> dict:
    """A phone-shaped kcall1 report: the VM fixture plus the layout keys
    the producer's CNDReportLayout adds (.m:3099-3108)."""
    report = _vm_kcall1_fixture()
    report["kernelLayout"] = MODULE.PHONE_LAYOUT_NAME
    report["kernelSlide"] = "0x0000000010000000"
    return report


class FakeSSH:
    """Scripted SSH stand-in: records commands, answers from a table."""

    def __init__(self, model: str, kernel: str,
                 kinds: dict[str, str] | None = None,
                 answers: dict[str, str] | None = None) -> None:
        self.model = model
        self.kernel = kernel
        self.kinds = kinds or {}
        self.answers = answers or {}
        self.commands: list[str] = []
        self.copies: list[tuple[Path, str]] = []

    def command(self, command: str) -> str:
        self.commands.append(command)
        for needle, answer in self.answers.items():
            if needle in command:
                return answer
        return f"{self.model}\n{self.kernel}\n"

    def file_kind(self, path: str) -> str:
        return self.kinds.get(path, "missing")

    def copy(self, source: Path, remote_path: str) -> None:
        self.copies.append((source, remote_path))


PHONE_KERNEL = ("Darwin Kernel Version 25.0.0: ...; "
                "root:xnu-12377.2.8~1/T8140 root:BUILD; 23A341")
VM_KERNEL = ("Darwin Kernel Version 25.1.0: ...; "
             "root:xnu-12377.42.6~55/RELEASE_ARM64_VRESEARCH1")
PHONE_KERNEL_ADDRESS = "0xfffffff017004000"   # container base + 0x10000000


def argparse_namespace(**fields):
    defaults = dict(host="x", port=22, user="root", known_hosts=None,
                    password_env="X", kernel_address=PHONE_KERNEL_ADDRESS,
                    hold=0, output=None)
    defaults.update(fields)
    return types.SimpleNamespace(**defaults)


def with_layout_constant(suffix: str, replacement: str) -> str:
    """The producer source with one CNDStaticPhone<suffix> value swapped."""
    source = TRIGGER_M.read_text()
    pattern = re.compile(
        rf"(static const uint64_t CNDStaticPhone{suffix} =\s*)"
        r"(CNDUnresolvedStatic|UINT64_C\(0x[0-9A-Fa-f]{16}\))(;)")
    swapped, count = pattern.subn(rf"\g<1>{replacement}\g<3>", source)
    assert count == 1, suffix
    return swapped


class ExplodingSSH:
    def __init__(self, *args, **kwargs) -> None:
        raise AssertionError("a device was contacted before every local "
                             "gate had passed")


def exploding_build(*args, **kwargs):
    raise AssertionError("the producer was built before every local gate "
                         "had passed")


class RequirePhysicalDeviceTests(unittest.TestCase):
    def test_accepts_the_exact_pinned_phone(self) -> None:
        ssh = FakeSSH("iPhone17,2", PHONE_KERNEL)
        MODULE.require_physical_device(ssh)
        self.assertIn("hw.model", ssh.commands[0])

    def test_refuses_the_vphone_guest(self) -> None:
        ssh = FakeSSH("VPHONE", VM_KERNEL)
        with self.assertRaises(LabError) as caught:
            MODULE.require_physical_device(ssh)
        self.assertIn("physical-device only", str(caught.exception))

    def test_refuses_a_different_model(self) -> None:
        ssh = FakeSSH("iPhone17,1", PHONE_KERNEL)
        with self.assertRaises(LabError) as caught:
            MODULE.require_physical_device(ssh)
        self.assertIn("expected the pinned phone", str(caught.exception))

    def test_refuses_a_different_os_build(self) -> None:
        ssh = FakeSSH("iPhone17,2", PHONE_KERNEL.replace("23A341", "23A999"))
        with self.assertRaises(LabError):
            MODULE.require_physical_device(ssh)

    def test_refuses_a_silent_target(self) -> None:
        class Silent(FakeSSH):
            def command(self, command: str) -> str:
                return "\n"
        with self.assertRaises(LabError):
            MODULE.require_physical_device(Silent("x", "y"))


class PhoneImageTests(unittest.TestCase):
    def test_verify_phone_image_accepts_the_pinned_artifacts(self) -> None:
        status = MODULE.verify_phone_image()
        self.assertEqual(status["staticBase"], "0xfffffff007c38000")
        self.assertGreaterEqual(status["symbolCount"], 39000)


class RouteTableTests(unittest.TestCase):
    def test_every_role_cites_a_real_producer_line(self) -> None:
        lines = TRIGGER_M.read_text().splitlines()
        for role in MODULE.ROUTE_ROLES:
            self.assertIn(role.m_constant, "".join(lines))
            text = lines[role.m_value_line - 1]
            self.assertIn(role.m_anchor, text,
                          f"{role.m_constant} anchor drifted at .m:"
                          f"{role.m_value_line}")

    def test_the_seven_kcall1_route_roles_are_all_present(self) -> None:
        roles = {role.role for role in MODULE.ROUTE_ROLES}
        self.assertEqual(roles, {
            "checkmulti_got_donor", "stock_callback", "init_ifnet_params",
            "stock_signer", "enoexec_return_stub", "load_w0_from_x0_stub",
            "ifnet_x0_dispatcher",
        })

    def test_every_route_entry_is_resolved_with_a_citation_or_an_gap(
            self) -> None:
        for role, entry in MODULE.PHONE_ROUTE.items():
            if entry.address is None:
                self.assertIn("unresolved", entry.citation)
                self.assertIn("owner/RE request", entry.citation)
            else:
                self.assertTrue(entry.citation.strip())
                self.assertNotIn("unresolved", entry.citation)

    def test_every_route_role_is_resolved_by_the_derivation(self) -> None:
        # All seven roles carry a derived phone address (implemented
        # level: static derivation only; nothing ran on the phone).
        self.assertEqual(MODULE.unresolved_roles(), [])
        self.assertEqual(set(MODULE.PHONE_ROUTE), {
            role.role for role in MODULE.ROUTE_ROLES})
        addresses = [entry.address for entry in MODULE.PHONE_ROUTE.values()]
        self.assertEqual(len(set(addresses)), len(addresses))

    def test_require_phone_route_passes_with_the_derived_table(self) -> None:
        MODULE.require_phone_route()

    def test_require_phone_route_refuses_any_unresolved_role(self) -> None:
        original = dict(MODULE.PHONE_ROUTE)
        try:
            MODULE.PHONE_ROUTE["stock_callback"] = MODULE.PhoneRouteEntry(
                None, MODULE.RE_PENDING)
            with self.assertRaises(LabError) as caught:
                MODULE.require_phone_route()
            message = str(caught.exception)
            self.assertIn("unresolved for: stock_callback", message)
            self.assertIn("No address is guessed", message)
            self.assertIn("Never scan or brute-force", message)
        finally:
            MODULE.PHONE_ROUTE.clear()
            MODULE.PHONE_ROUTE.update(original)

    def test_every_resolved_entry_cites_an_existing_record_line(self) -> None:
        # A citation names the derivation record file(s) and the line(s)
        # that carry the resolved address; those lines must exist in the
        # checked-in record and must contain the address.
        self.assertTrue(MODULE.DERIVATION_DIR.is_dir())
        for role, entry in MODULE.PHONE_ROUTE.items():
            self.assertIsNotNone(entry.address, role)
            citations = re.findall(r"([a-z-]+\.txt):(\d+)(?:-(\d+))?",
                                   entry.citation)
            self.assertTrue(citations, role)
            record, start, end = citations[0]
            lines = (MODULE.DERIVATION_DIR / record).read_text().splitlines()
            window = "\n".join(lines[int(start) - 1:int(end or start)])
            self.assertIn(f"{entry.address:x}", window,
                          f"{role}: {record}:{start} lacks the address")

    def test_the_phone_route_keeps_the_vm_signer_relation(self) -> None:
        # The VM pins stock_signer = init_ifnet_params + 0x1b8
        # (.m:102-104); the phone derivation located the same step at
        # the same offset (phone-kext-find.txt:150 vm-offset-match true).
        vm = {role.role: role.vm_static for role in MODULE.ROUTE_ROLES}
        self.assertEqual(vm["stock_signer"] - vm["init_ifnet_params"], 0x1B8)
        phone = {role: entry.address
                 for role, entry in MODULE.PHONE_ROUTE.items()}
        self.assertEqual(
            phone["stock_signer"] - phone["init_ifnet_params"], 0x1B8)

    def test_the_load_stub_pin_rejects_the_shape_only_second_claimant(
            self) -> None:
        # load-stub-reconciliation.txt: two stubs in this build decode
        # `bti c; ldr w0,[x0]; ret`. The role stays the one that
        # reproduces the VM pin's 6-element outline run element for
        # element (fffffff008a4b130); the other (fffffff00826a470,
        # Cyanide/CNDPhysicalIOUserEthernetSignerProbe.m:38-39) is the
        # counterpart of the VM's non-BTI fffffe0007b19544 - a
        # shape-selected, unreferenced constant, not a second derivation.
        rejected = 0xFFFFFFF00826A470
        self.assertEqual(MODULE.PHONE_ROUTE["load_w0_from_x0_stub"].address,
                         0xFFFFFFF008A4B130)
        self.assertNotIn(rejected, {entry.address
                                    for entry in MODULE.PHONE_ROUTE.values()})
        probe = (TRIGGER_M.parents[2] /
                 "Cyanide/CNDPhysicalIOUserEthernetSignerProbe.m").read_text()
        self.assertIn("UINT64_C(0xfffffff00826a470);", probe)
        self.assertEqual(probe.count("CNDPhysicalSignerStaticLoadW0FromX0"), 1)
        record = (MODULE.DERIVATION_DIR /
                  "load-stub-reconciliation.txt").read_text()
        self.assertIn("fffffff008a4b130", record)
        self.assertIn("fffffff00826a470", record)

    def test_the_stock_callback_agrees_with_the_got_donor_fixup(self) -> None:
        # Two independent witnesses: the unique bti-prefixed body match
        # and the __got donor's chained-fixup target offset rebased on the
        # kernelcache container (phone-kernelcache-header.txt:6).
        record = (MODULE.DERIVATION_DIR / "phone-kext-find.txt").read_text()
        raw = re.search(r"GOT-SLOT fffffff0080b4020 .* raw8 0x([0-9a-f]+)",
                        record)
        self.assertIsNotNone(raw)
        target = int(raw.group(1), 16) & 0xFFFFFFFF
        self.assertEqual(
            MODULE.PHONE_KERNELCACHE_CONTAINER_BASE + target,
            MODULE.PHONE_ROUTE["stock_callback"].address)
        header = (MODULE.DERIVATION_DIR
                  / "phone-kernelcache-header.txt").read_text()
        self.assertIn("vmaddr 0xfffffff007004000", header)

    def test_a_resolved_entry_without_citation_is_rejected(self) -> None:
        original = dict(MODULE.PHONE_ROUTE)
        try:
            first = next(iter(MODULE.PHONE_ROUTE))
            MODULE.PHONE_ROUTE[first] = MODULE.PhoneRouteEntry(
                0xFFFFFFF008000000, "   ")
            with self.assertRaises(LabError) as caught:
                MODULE.require_phone_route()
            self.assertIn("refusing", str(caught.exception))
        finally:
            MODULE.PHONE_ROUTE.clear()
            MODULE.PHONE_ROUTE.update(original)


class AllProcDerivationTests(unittest.TestCase):
    RECORD = "phone-allproc-find.txt"

    def test_the_allproc_record_self_checks_against_the_vphone_pin(
            self) -> None:
        # The method (unique proc_iterate-shaped function; bit-0 guarded
        # head load; zombproc at +8) must reproduce the VM pin
        # (.m:26 CNDStaticAllProc) on the research kernel before the
        # phone value is trusted.
        text = (MODULE.DERIVATION_DIR / self.RECORD).read_text()
        lines = text.splitlines()
        m_lines = TRIGGER_M.read_text().splitlines()
        self.assertIn("CNDStaticAllProc =", m_lines[25])          # .m:26
        self.assertIn("UINT64_C(0xfffffe0009813020)", m_lines[26])  # .m:27
        self.assertIn("SELF-CHECK expect fffffe0009813020 match true", text)
        self.assertIn("SELF-CHECK expect fffffe0009813020 candidate "
                      "fffffe0009813020 match true", text)
        vm_scan = [line for line in lines
                   if line.startswith("MATCH ") and "fffffe00" in line]
        self.assertEqual(len(vm_scan), 1)
        self.assertIn("allproc fffffe0009813020 zombproc fffffe0009813028",
                      vm_scan[0])

    def test_the_phone_allproc_is_unique_named_and_twice_witnessed(
            self) -> None:
        text = (MODULE.DERIVATION_DIR / self.RECORD).read_text()
        lines = text.splitlines()
        entry = MODULE.PHONE_LAYOUT_STATICS["AllProc"]
        self.assertEqual(entry.address, 0xFFFFFFF00B2FAA18)
        phone_scan = [line for line in lines
                      if line.startswith("MATCH ") and "fffffff0" in line]
        self.assertEqual(len(phone_scan), 1)
        self.assertIn("fffffff008726f6c", phone_scan[0])
        self.assertIn("allproc fffffff00b2faa18 zombproc fffffff00b2faa20",
                      phone_scan[0])
        self.assertIn("SYMBOL-MAP fffffff008726f6c _proc_iterate", text)
        self.assertIn("ALLPROC-CANDIDATE fffffff00b2faa18", text)
        self.assertIn("PHONE-ALLPROC-CANDIDATE-COUNT 1", text)
        self.assertIn("REF-TO-COUNT fffffff00b2faa18 15 functions 8", text)
        self.assertIn("REF-TO-COUNT fffffe0009813020 15 functions 8", text)
        self.assertIn("SYMBOL-MAP fffffff008723ea8 _pinsertchild", text)
        # The pinned symbol map really names the walker at that address.
        symbols = json.loads(MODULE.PHONE_SYMBOLS.read_text())
        self.assertEqual(symbols[str(0xFFFFFFF008726F6C)], "_proc_iterate")
        # The citation's record lines carry the address.
        for start, end in re.findall(
                r"phone-allproc-find\.txt:(\d+)(?:-(\d+))?", entry.citation)[:1]:
            window = "\n".join(lines[int(start) - 1:int(end or start)])
            self.assertIn("fffffff00b2faa18", window)

    def test_the_phone_allproc_is_a_phone_static_not_a_vm_pin(self) -> None:
        address = MODULE.PHONE_LAYOUT_STATICS["AllProc"].address
        self.assertEqual(address & 0xFFFFFFF000000000, 0xFFFFFFF000000000)
        self.assertGreater(address, MODULE.PHONE_KERNELCACHE_CONTAINER_BASE)
        self.assertNotEqual(address, 0xFFFFFE0009813020)
        self.assertEqual(address & 7, 0)


class ProducerSupportTests(unittest.TestCase):
    EXPECTED_ELEMENTS = {
        "KernelBase", "AllProc", "ZoneMin", "ZoneMax",
        "IOEthernetCheckMultiGOT", "EtherCheckMulti",
        "IOEthernetInitIfnetParams", "IOEthernetCheckMultiSigner",
        "ENOEXECReturn", "LoadW0FromX0", "IfnetX0Dispatcher",
    }

    def test_the_producer_phone_block_is_reflected_and_complete(self) -> None:
        # The landed CNDStaticPhone* block carries every layout element
        # with a derived value; the anchor pins on the vPhone constants
        # still hold; nothing is unresolved.
        constants = MODULE.phone_layout_constants()
        self.assertEqual(set(constants), self.EXPECTED_ELEMENTS)
        self.assertNotIn(None, constants.values())
        self.assertEqual(MODULE.phone_layout_unresolved(), [])
        MODULE.require_producer_physical_support()
        MODULE.require_phone_layout_complete()

    def test_the_producer_phone_constants_agree_with_the_derivation(
            self) -> None:
        constants = MODULE.phone_layout_constants()
        for role, suffix in MODULE.PHONE_LAYOUT_ROUTE_CONSTANTS.items():
            self.assertEqual(constants[suffix],
                             MODULE.PHONE_ROUTE[role].address, role)
        for suffix, entry in MODULE.PHONE_LAYOUT_STATICS.items():
            self.assertEqual(constants[suffix], entry.address, suffix)
        self.assertEqual(constants["KernelBase"],
                         MODULE.PHONE_KERNELCACHE_CONTAINER_BASE)

    def test_the_vphone_constants_are_byte_identical_to_the_pins(self) -> None:
        lines = TRIGGER_M.read_text().splitlines()
        self.assertIn("UINT64_C(0xfffffe0007004000)", lines[24])  # .m:25
        self.assertIn("CNDStaticAllProc =", lines[25])             # .m:26
        self.assertIn("UINT64_C(0xfffffe0009813020)", lines[26])  # .m:27
        for role in MODULE.ROUTE_ROLES:
            self.assertIn(role.m_anchor, lines[role.m_value_line - 1])
        self.assertIn("CNDZoneMin = UINT64_C(0xfffffe1000000000)", lines[115])
        self.assertIn("CNDZoneMax = UINT64_C(0xfffffe3fffffffff)", lines[116])

    def test_a_drifted_producer_anchor_is_detected(self) -> None:
        role = MODULE.ROUTE_ROLES[0]
        lines = TRIGGER_M.read_text().splitlines()
        real = lines[role.m_value_line - 1]
        lines[role.m_value_line - 1] = real.replace(
            role.m_anchor, "UINT64_C(0x0000000000000000)")
        with unittest.mock.patch.object(
                Path, "read_text", return_value="\n".join(lines)):
            with self.assertRaises(LabError) as caught:
                MODULE.require_producer_physical_support()
        self.assertIn("drifted", str(caught.exception))
        self.assertIn(role.m_constant, str(caught.exception))

    def test_a_producer_without_the_phone_block_is_refused(self) -> None:
        source = TRIGGER_M.read_text()
        stripped = re.sub(r"static const uint64_t CNDStaticPhone\w+ =\s*"
                          r"[^;]+;", "", source)
        with unittest.mock.patch.object(
                Path, "read_text", return_value=stripped):
            with self.assertRaises(LabError) as caught:
                MODULE.require_producer_physical_support()
        self.assertIn("CNDStaticPhone", str(caught.exception))

    def test_an_unresolved_layout_element_is_reflected_not_hidden(
            self) -> None:
        swapped = with_layout_constant("AllProc", "CNDUnresolvedStatic")
        with unittest.mock.patch.object(
                Path, "read_text", return_value=swapped):
            self.assertEqual(MODULE.phone_layout_unresolved(), ["AllProc"])
            MODULE.require_producer_physical_support()  # reflects, no refusal
            with self.assertRaises(LabError) as caught:
                MODULE.require_phone_layout_complete()
        message = str(caught.exception)
        self.assertIn("unresolved for: AllProc", message)
        self.assertIn("No address is guessed", message)
        self.assertIn("Never scan or brute-force", message)

    def test_a_missing_layout_element_counts_as_unresolved(self) -> None:
        source = TRIGGER_M.read_text()
        stripped = re.sub(r"static const uint64_t CNDStaticPhoneZoneMax =\s*"
                          r"[^;]+;", "", source)
        with unittest.mock.patch.object(
                Path, "read_text", return_value=stripped):
            self.assertEqual(MODULE.phone_layout_unresolved(), ["ZoneMax"])
            with self.assertRaises(LabError) as caught:
                MODULE.require_producer_physical_support()
        self.assertIn("no CNDStaticPhoneZoneMax", str(caught.exception))

    def test_a_producer_constant_disagreeing_with_the_derivation_is_refused(
            self) -> None:
        swapped = with_layout_constant(
            "EtherCheckMulti", "UINT64_C(0xfffffff008490450)")
        with unittest.mock.patch.object(
                Path, "read_text", return_value=swapped):
            with self.assertRaises(LabError) as caught:
                MODULE.require_producer_physical_support()
        message = str(caught.exception)
        self.assertIn("CNDStaticPhoneEtherCheckMulti", message)
        self.assertIn("disagrees with the derivation", message)

    def test_a_missing_unresolved_marker_is_a_drift(self) -> None:
        source = TRIGGER_M.read_text().replace(
            MODULE.PHONE_LAYOUT_UNRESOLVED_MARKER, "")
        with unittest.mock.patch.object(
                Path, "read_text", return_value=source):
            with self.assertRaises(LabError) as caught:
                MODULE.phone_layout_constants()
        self.assertIn("CNDUnresolvedStatic marker", str(caught.exception))


class PhysicalKRWSourceTests(unittest.TestCase):
    def test_the_provider_physical_krw_anchors_exist_as_cited(self) -> None:
        MODULE.require_physical_krw_sources()

    def test_a_drifted_provider_anchor_is_detected(self) -> None:
        lines = PROVIDER_C.read_text().splitlines()
        anchor, start, end = MODULE.PHYSICAL_KRW_ANCHORS[0]
        for index in range(start - 1, end):
            lines[index] = lines[index].replace(anchor, "removed")
        with unittest.mock.patch.object(
                Path, "read_text", return_value="\n".join(lines)):
            with self.assertRaises(LabError) as caught:
                MODULE.require_physical_krw_sources()
        self.assertIn("physical KRW source drifted", str(caught.exception))


class KernelAddressTests(unittest.TestCase):
    def test_accepts_a_page_slid_phone_container_base(self) -> None:
        self.assertEqual(
            MODULE.require_phone_kernel_address("0xFFFFFFF017004000"),
            "0xfffffff017004000")
        self.assertEqual(
            MODULE.require_phone_kernel_address("0xfffffff007004000"),
            "0xfffffff007004000")

    def test_refuses_a_missing_or_malformed_address(self) -> None:
        with self.assertRaises(LabError) as caught:
            MODULE.require_phone_kernel_address(None)
        self.assertIn("--kernel-address", str(caught.exception))
        with self.assertRaises(LabError):
            MODULE.require_phone_kernel_address("fffffff017004000")

    def test_refuses_a_vm_shaped_address(self) -> None:
        with self.assertRaises(LabError) as caught:
            MODULE.require_phone_kernel_address("0xfffffe0007004000")
        self.assertIn("below the phone container base", str(caught.exception))

    def test_refuses_an_unaligned_or_oversized_slide(self) -> None:
        with self.assertRaises(LabError):
            MODULE.require_phone_kernel_address("0xfffffff007005000")
        with self.assertRaises(LabError):
            MODULE.require_phone_kernel_address("0xfffffff107004000")


class RunFlowTests(unittest.TestCase):
    def test_run_kcall1_route_gate_still_fires_first(self) -> None:
        original = dict(MODULE.PHONE_ROUTE)
        try:
            MODULE.PHONE_ROUTE["ifnet_x0_dispatcher"] = \
                MODULE.PhoneRouteEntry(None, MODULE.RE_PENDING)
            with unittest.mock.patch.object(
                    MODULE, "require_producer_physical_support",
                    side_effect=AssertionError("producer gate ran before "
                                               "the route gate")), \
                    unittest.mock.patch.object(MODULE, "SSH", ExplodingSSH), \
                    unittest.mock.patch.object(MODULE, "build_binary",
                                               exploding_build):
                with self.assertRaises(LabError) as caught:
                    MODULE.run_kcall1(argparse_namespace())
            self.assertIn("route table is unresolved", str(caught.exception))
        finally:
            MODULE.PHONE_ROUTE.clear()
            MODULE.PHONE_ROUTE.update(original)

    def test_run_kcall1_refuses_an_unresolved_layout_element_before_contact(
            self) -> None:
        with unittest.mock.patch.object(
                MODULE, "phone_layout_unresolved", return_value=["AllProc"]), \
                unittest.mock.patch.object(MODULE, "SSH", ExplodingSSH), \
                unittest.mock.patch.object(MODULE, "build_binary",
                                           exploding_build):
            with self.assertRaises(LabError) as caught:
                MODULE.run_kcall1(argparse_namespace())
        self.assertIn("phone layout is unresolved for: AllProc",
                      str(caught.exception))

    def test_run_kcall1_refuses_a_disagreeing_producer_before_contact(
            self) -> None:
        swapped = with_layout_constant(
            "IfnetX0Dispatcher", "UINT64_C(0xfffffff00a6e75a0)")
        real_read_text = Path.read_text

        def read_text(self, *args, **kwargs):
            if self == MODULE.TRIGGER_SOURCE:
                return swapped
            return real_read_text(self, *args, **kwargs)

        with unittest.mock.patch.object(Path, "read_text", read_text), \
                unittest.mock.patch.object(MODULE, "SSH", ExplodingSSH), \
                unittest.mock.patch.object(MODULE, "build_binary",
                                           exploding_build):
            with self.assertRaises(LabError) as caught:
                MODULE.run_kcall1(argparse_namespace())
        self.assertIn("disagrees with the derivation", str(caught.exception))

    def test_run_kcall1_refuses_a_bad_kernel_address_before_contact(
            self) -> None:
        with unittest.mock.patch.object(MODULE, "SSH", ExplodingSSH), \
                unittest.mock.patch.object(MODULE, "build_binary",
                                           exploding_build):
            with self.assertRaises(LabError) as caught:
                MODULE.run_kcall1(argparse_namespace(kernel_address=None))
            self.assertIn("--kernel-address", str(caught.exception))
            with self.assertRaises(LabError) as caught:
                MODULE.run_kcall1(argparse_namespace(
                    kernel_address="0xfffffe0007004000"))
            self.assertIn("below the phone container base",
                          str(caught.exception))

    def test_run_kcall1_gate_order_precedes_build_and_contact(self) -> None:
        order: list[str] = []
        names = ("verify_phone_image", "require_phone_route",
                 "require_producer_physical_support",
                 "require_phone_layout_complete",
                 "require_physical_krw_sources")
        patches = [unittest.mock.patch.object(
            MODULE, name, side_effect=lambda *a, _n=name, **k: order.append(_n))
            for name in names]
        patches.append(unittest.mock.patch.object(
            MODULE, "require_phone_kernel_address",
            side_effect=lambda v: (order.append("kernel_address"), v)[1]))
        patches.append(unittest.mock.patch.object(
            MODULE, "build_binary",
            side_effect=lambda *a, **k: (order.append("build"),
                                         exploding_build())[1]))
        patches.append(unittest.mock.patch.object(MODULE, "SSH", ExplodingSSH))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        with self.assertRaises(AssertionError):
            MODULE.run_kcall1(argparse_namespace())
        self.assertEqual(order, [*names, "kernel_address", "build"])

    def _built(self, tmp_name: str = "trigger") -> Path:
        import tempfile
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(directory))
        built = directory / tmp_name
        built.write_bytes(b"not-a-real-binary")
        return built

    def test_run_kcall1_refuses_the_vphone_guest_after_build_no_staging(
            self) -> None:
        ssh = FakeSSH("VPHONE", VM_KERNEL)
        with unittest.mock.patch.object(
                MODULE, "build_binary", return_value=self._built()), \
                unittest.mock.patch.object(MODULE, "SSH",
                                           lambda *a, **k: ssh), \
                unittest.mock.patch.object(
                    MODULE, "copy_binary",
                    side_effect=AssertionError("staged on a vPhone")):
            with self.assertRaises(LabError) as caught:
                MODULE.run_kcall1(argparse_namespace())
        self.assertIn("physical-device only", str(caught.exception))
        self.assertEqual(len(ssh.commands), 1)
        self.assertIn("hw.model", ssh.commands[0])

    def test_run_kcall1_refuses_without_the_phone_krw_socket(self) -> None:
        ssh = FakeSSH("iPhone17,2", PHONE_KERNEL)
        with unittest.mock.patch.object(
                MODULE, "build_binary", return_value=self._built()), \
                unittest.mock.patch.object(MODULE, "SSH",
                                           lambda *a, **k: ssh), \
                unittest.mock.patch.object(
                    MODULE, "copy_binary",
                    side_effect=AssertionError("staged without a KRW lease")):
            with self.assertRaises(LabError) as caught:
                MODULE.run_kcall1(argparse_namespace())
        self.assertIn("KRW provider is not running", str(caught.exception))
        self.assertEqual(len(ssh.commands), 1)

    def test_run_kcall1_refuses_without_the_donor_entitlement(self) -> None:
        ssh = FakeSSH("iPhone17,2", PHONE_KERNEL,
                      kinds={MODULE.STANDALONE_KRW_SOCKET_PATH: "socket"},
                      answers={"ldid": "<plist/>"})
        with unittest.mock.patch.object(
                MODULE, "build_binary", return_value=self._built()), \
                unittest.mock.patch.object(MODULE, "SSH",
                                           lambda *a, **k: ssh), \
                unittest.mock.patch.object(
                    MODULE, "copy_binary",
                    side_effect=AssertionError("staged without a donor")):
            with self.assertRaises(LabError) as caught:
                MODULE.run_kcall1(argparse_namespace())
        self.assertIn(MODULE.DONOR_ENTITLEMENT, str(caught.exception))

    def _scripted_phone(self, report: dict) -> FakeSSH:
        return FakeSSH(
            "iPhone17,2", PHONE_KERNEL,
            kinds={MODULE.STANDALONE_KRW_SOCKET_PATH: "socket"},
            answers={
                "ldid": f"<key>{MODULE.DONOR_ENTITLEMENT}</key>",
                "ps -axo": f"1 /sbin/launchd\n77 {MODULE.DONOR_EXECUTABLE}\n",
                "--ifnet-kcall1-pac-canary": json.dumps(report),
            })

    def test_run_kcall1_end_to_end_with_a_scripted_phone(self) -> None:
        ssh = self._scripted_phone(phone_kcall1_report())
        built = self._built()
        staged: list[tuple[Path, str]] = []

        def copy_binary(ssh_, local, stem):
            staged.append((local, stem))
            return f"/var/tmp/{stem}-deadbeef"

        with unittest.mock.patch.object(
                MODULE, "build_binary", return_value=built) as build, \
                unittest.mock.patch.object(MODULE, "SSH",
                                           lambda *a, **k: ssh), \
                unittest.mock.patch.object(MODULE, "copy_binary", copy_binary):
            observation = MODULE.run_kcall1(argparse_namespace(hold=5))
        build.assert_called_once_with(
            MODULE.TRIGGER_SOURCE, "cnd_iouserethernet_krw_trigger",
            architecture="arm64e", frameworks=("Foundation", "IOKit"))
        self.assertEqual(staged, [(built, "cnd-iouserethernet-krw-phone")])
        run_command = ssh.commands[-1]
        self.assertTrue(run_command.startswith(
            "/var/tmp/cnd-iouserethernet-krw-phone-deadbeef "))
        self.assertIn(MODULE.STANDALONE_KRW_SOCKET_PATH, run_command)
        self.assertIn(f" {PHONE_KERNEL_ADDRESS} 77 ", run_command)
        self.assertTrue(run_command.endswith(
            "--ifnet-kcall1-pac-canary --hold 5"))
        self.assertEqual(observation["schema"], MODULE.OBSERVATION_SCHEMA)
        self.assertEqual(observation["kernelLayout"], MODULE.PHONE_LAYOUT_NAME)
        self.assertEqual(observation["kernelAddress"], PHONE_KERNEL_ADDRESS)
        self.assertEqual(observation["mode"], MODULE.MODE_KCALL1)
        self.assertEqual(observation["level"], MODULE.LEVEL_PHYSICAL_PROVED)
        self.assertEqual(observation["result"]["result"],
                         "krw-ifnet-kcall1-chosen-pc-x0-executed")
        self.assertNotIn("KernelCall",
                         observation["result"]["providerOperations"])

    def test_run_kcall1_rejects_a_report_that_ran_the_vphone_layout(
            self) -> None:
        report = phone_kcall1_report()
        report["kernelLayout"] = "vphone-23A341"
        ssh = self._scripted_phone(report)
        with unittest.mock.patch.object(
                MODULE, "build_binary", return_value=self._built()), \
                unittest.mock.patch.object(MODULE, "SSH",
                                           lambda *a, **k: ssh), \
                unittest.mock.patch.object(
                    MODULE, "copy_binary",
                    return_value="/var/tmp/cnd-iouserethernet-krw-phone-x"):
            with self.assertRaises(LabError) as caught:
                MODULE.run_kcall1(argparse_namespace())
        self.assertIn("did not run on the phone layout", str(caught.exception))

    def test_run_kcall1_rejects_non_json_output(self) -> None:
        ssh = self._scripted_phone({})
        ssh.answers["--ifnet-kcall1-pac-canary"] = "panic?"
        with unittest.mock.patch.object(
                MODULE, "build_binary", return_value=self._built()), \
                unittest.mock.patch.object(MODULE, "SSH",
                                           lambda *a, **k: ssh), \
                unittest.mock.patch.object(
                    MODULE, "copy_binary",
                    return_value="/var/tmp/cnd-iouserethernet-krw-phone-x"):
            with self.assertRaises(LabError) as caught:
                MODULE.run_kcall1(argparse_namespace())
        self.assertIn("did not return JSON", str(caught.exception))

    def test_run_kcall1_refuses_the_vm_syscall_backend_by_design(
            self) -> None:
        source = MODULE_PATH.read_text()
        self.assertNotIn("syscall 439", source)
        self.assertNotIn("require_vphone", source)
        self.assertIn("libkrw-tfp0", source)


class SharedValidatorTests(unittest.TestCase):
    def test_the_phone_port_reuses_the_shared_kcall1_validator(self) -> None:
        source = inspect.getsource(MODULE.validate_phone_kcall1_report)
        self.assertIn("require_ifnet_kcall1_pac_canary=True", source)
        self.assertIn("validate_result", source)

    def test_the_shared_validator_accepts_a_phone_layout_report(self) -> None:
        result = MODULE.validate_phone_kcall1_report(phone_kcall1_report())
        self.assertEqual(result["kernelLayout"], MODULE.PHONE_LAYOUT_NAME)

    def test_the_shared_validator_still_refuses_a_kernelcall_report(
            self) -> None:
        report = phone_kcall1_report()
        report["ifnetKCall1ProviderKCallUsed"] = True
        with self.assertRaises(LabError):
            MODULE.validate_phone_kcall1_report(report)

    def test_an_unresolved_layout_report_is_refused(self) -> None:
        report = phone_kcall1_report()
        report["kernelLayoutUnresolved"] = "AllProc"
        with self.assertRaises(LabError) as caught:
            MODULE.validate_phone_kcall1_report(report)
        self.assertIn("unresolved layout element", str(caught.exception))


class VerifyTests(unittest.TestCase):
    def test_verify_reports_route_and_layout_status_honestly(self) -> None:
        ssh = FakeSSH("iPhone17,2", PHONE_KERNEL)
        with unittest.mock.patch.object(MODULE, "SSH", lambda *a, **k: ssh):
            status = MODULE.verify(argparse_namespace())
        self.assertEqual(status["routeUnresolved"], [])
        self.assertEqual(status["phoneLayoutUnresolved"], [])
        self.assertTrue(status["producerPhysicalSupport"])
        self.assertEqual(status["phoneLayout"], MODULE.PHONE_LAYOUT_NAME)
        self.assertEqual(status["krwSocket"], "missing")
        self.assertEqual(status["level"], MODULE.LEVEL_PHYSICAL_IMPLEMENTED)

    def test_verify_surfaces_an_unresolved_layout_element(self) -> None:
        ssh = FakeSSH("iPhone17,2", PHONE_KERNEL,
                      kinds={MODULE.STANDALONE_KRW_SOCKET_PATH: "socket"})
        with unittest.mock.patch.object(MODULE, "SSH", lambda *a, **k: ssh), \
                unittest.mock.patch.object(
                    MODULE, "phone_layout_unresolved",
                    return_value=["AllProc"]):
            status = MODULE.verify(argparse_namespace())
        self.assertEqual(status["phoneLayoutUnresolved"], ["AllProc"])
        self.assertEqual(status["krwSocket"], "socket")

    def test_verify_refuses_the_vphone(self) -> None:
        ssh = FakeSSH("VPHONE", VM_KERNEL)
        with unittest.mock.patch.object(MODULE, "SSH", lambda *a, **k: ssh):
            with self.assertRaises(LabError):
                MODULE.verify(argparse_namespace())


class HygieneTests(unittest.TestCase):
    def test_the_vm_paths_still_gate_run_live_with_require_vphone(
            self) -> None:
        source = VM_TRIGGER_PY.read_text()
        self.assertIn("require_vphone(ssh)", source)

    def test_the_vm_mode_and_producer_constants_are_untouched(self) -> None:
        # The VM trigger module still pins its own vPhone constants and
        # modes; the port must not have drifted its producer citations.
        source = VM_TRIGGER_PY.read_text()
        self.assertIn('"ifnet-kcall1-pac-canary"', source)
        self.assertIn("PRODUCER_CONSTANTS", source)

    def test_the_phone_route_table_has_no_guessed_addresses(self) -> None:
        for entry in MODULE.PHONE_ROUTE.values():
            if entry.address is None:
                continue
            # A resolved phone address must lie in the iPhone17,2
            # kernelcache's static space, above the container base, and
            # must not be a VM (0xfffffe00...) pin carried over.
            self.assertEqual(entry.address & 0xFFFFFFF000000000,
                             0xFFFFFFF000000000)
            self.assertGreater(entry.address,
                               MODULE.PHONE_KERNELCACHE_CONTAINER_BASE)
            self.assertNotIn(entry.address,
                             {role.vm_static for role in MODULE.ROUTE_ROLES})

    def test_the_owner_requests_name_the_live_run_as_the_remaining_step(
            self) -> None:
        labels = [label for label, _ in MODULE.OWNER_REQUESTS]
        self.assertTrue(any("live phone run" in label for label in labels))
        self.assertTrue(any("landed" in label and ".m" in label
                            for label in labels))


if __name__ == "__main__":
    unittest.main()
