"""Tests for the read-only physical panic-signature probe.

The probe is the permitted physical-device subset of the 2026-10-15 VM
lab-provider panic follow-up: it only reads panic reports. These tests pin
that boundary and the parser/classifier against a VM-shaped fixture and a
physical-shaped fixture.
"""

import json
import re
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))

import cnd_physical_panic_signature_probe as probe  # noqa: E402


VM_PANIC_STRING = (
    "panic(cpu 1 caller 0xfffffe004127cf70): Kernel data abort. at pc "
    "0xfffffe004128317c, lr 0x8cc17e0040bc5e78 (saved state: 0xfffffea76a8474c0)\n"
    "\t  x0:  0xfffffe15e40c2760 x1:  0xfffffe3613078b08  x2:  0x0000000000000018 "
    "x3:  0xfffffe15e40c2760\n"
    "\t  x4:  0x0000000000000001 x5:  0x0000000000000001  x6:  0x0000000000000000 "
    "x7:  0xfffffea76a847bc8\n"
    "\t  pc:  0xfffffe004128317c cpsr: 0x20400204         esr: 0x000000009600004f  "
    "far: 0xfffffe15e40c2760\n"
    "\n"
    "Debugger message: panic\n"
    "OS version: 23A341\n"
    "Kernel version: Darwin Kernel Version 25.1.0: Thu Oct 23 11:11:48 PDT 2025; "
    "root:xnu-12377.42.6~55/RELEASE_ARM64_VRESEARCH1\n"
    "Kernel slide:      0x0000000038f7c000\n"
    "Kernel text base:  0xfffffe003ff80000\n"
    "Kernel text exec slide: 0x0000000039a28000\n"
    "Kernel text exec base:  0xfffffe0040a2c000\n"
    "\n"
    "Probabilistic GZAlloc Report:\n"
    "  Zone    : MAC Labels\n"
    "  Address : 0xfffffe15e40c2760\n"
    "  Submap  : RO [0xfffffe15e2000000; 0xfffffe187c000000)\n"
    "  Kind    : use-after-free (medium confidence)\n"
    "  Metadata: zid:4 inl:0 cl:0x1 0x37a0 0x60002ae0 0xf857902f 0x0000f028\n"
    "\n"
    "Panicked task 0xfffffe28df9490e8: 724 pages, 1 threads: pid 591: "
    "cnd-provide-tfp0-1c2cf1413dabb50\n"
    "Panicked thread: 0xfffffe28dfbedbd0, backtrace: 0xfffffea76a846a60, tid: 10354\n"
    "\t\t  lr: 0xfffffe0040a71164  fp: 0xfffffea76a846ae0\n"
    "\t\t  lr: 0xfffffe004128317c  fp: 0xfffffea76a847810\n"
    "\t\t  lr: 0xfffffe0040bc5e78  fp: 0xfffffea76a847870\n"
    "\t\t  lr: 0x000000023dbaecd4  fp: 0x0000000000000000\n"
    "\n"
    "last started kext at 219946247: com.apple.driver.AppleUSBDeviceMux\n"
)

PHYSICAL_PANIC_STRING = (
    "panic(cpu 4 caller 0xfffffff03bd919bc): Unexpected fault in kernel physical "
    "aperture at pc 0xfffffff03bd97a7c, lr 0x9ea8cdf03b6e21e8 (saved state: "
    "0xffffffe409287470)\n"
    "\t  x0:  0xfffffff1f47e4000 x1:  0x0000000000000000  x2:  0x0000000000000008 "
    "x3:  0x0000000000000000\n"
    "\t  pc:  0xfffffff03bd97a7c cpsr: 0x60400204         esr: 0x0000000096000007  "
    "far: 0xfffffff1f47e4000\n"
    "\n"
    "Kernel version: Darwin Kernel Version 25.0.0: Tue Aug 26 20:30:59 PDT 2025; "
    "root:xnu-12377.2.8~1/RELEASE_ARM64_T8140\n"
    "Kernel slide:      0x0000000033340000\n"
    "Kernel text base:  0xfffffff03a344000\n"
    "Kernel text exec base:  0xfffffff03b518000\n"
    "\n"
    "Panicked task 0xffffffe0cd507408: 19924 pages, 12 threads: pid 683: Cyanide\n"
    "Panicked thread: 0xffffffdd3c76e950, backtrace: 0xffffffe409286ac0, tid: 144002\n"
    "\t\t  lr: 0xfffffff03b5a1164  fp: 0xffffffe409286b50\n"
    "\t\t  lr: 0x00000001048d2c10  fp: 0x0000000000000000\n"
    "\n"
)


def write_ips(directory: Path, name: str, *, product: str, kernel: str,
              panic_string: str, os_version: str = "iPhone OS 26.0 (23A341)") -> Path:
    metadata = {
        "bug_type": "210",
        "timestamp": "2026-10-15 17:19:00.00 -0400",
        "os_version": os_version,
        "incident_id": "C19CF6AD-3B64-4C9B-BC64-B0508705EC3B",
    }
    payload = {"product": product, "kernel": kernel, "panicString": panic_string}
    path = directory / name
    path.write_text(json.dumps(metadata) + "\n" + json.dumps(payload, indent=2))
    return path


class PhysicalPanicSignatureProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (
            ROOT / "scripts/lab/cnd_physical_panic_signature_probe.py"
        ).read_text()
        cls.vm_harness = (ROOT / "scripts/lab/cnd_vphone_krw.py").read_text()
        cls.vm_lab = (ROOT / "scripts/lab/cnd_remotecall_lab.py").read_text()
        cls.provider_header = (
            ROOT / "Cyanide/kexploit/CNDLabKernelProvider.h"
        ).read_text()
        cls.vm_guide = (ROOT / "docs/research/vm-guide.md").read_text()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cnd-panic-sig-")
        self.directory = Path(self.temporary.name)
        self.vm_report = write_ips(
            self.directory, "panic-full-2026-10-15-171900.0002.ips",
            product="iPhone99,11",
            kernel="Darwin Kernel Version 25.1.0; root:xnu-12377.42.6~55/"
                   "RELEASE_ARM64_VRESEARCH1",
            panic_string=VM_PANIC_STRING,
        )
        self.physical_report = write_ips(
            self.directory, "panic-full-2026-10-12-113515.0002.ips",
            product="iPhone17,2",
            kernel="Darwin Kernel Version 25.0.0; root:xnu-12377.2.8~1/"
                   "RELEASE_ARM64_T8140",
            panic_string=PHYSICAL_PANIC_STRING,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    # --- parser -----------------------------------------------------------

    def test_parses_vm_shaped_report(self) -> None:
        report = probe.parse_panic_report(self.vm_report)
        self.assertEqual(report.panic_kind, "Kernel data abort")
        self.assertEqual(report.panicked_pid, 591)
        self.assertEqual(report.panicked_process, "cnd-provide-tfp0-1c2cf1413dabb50")
        self.assertEqual(report.esr, 0x9600004F)
        self.assertEqual(report.far, 0xFFFFFE15E40C2760)
        self.assertEqual(report.registers["x2"], 0x18)
        self.assertIsNotNone(report.gzalloc)
        self.assertEqual(report.gzalloc.zone, "MAC Labels")
        self.assertEqual(report.gzalloc.address, 0xFFFFFE15E40C2760)
        self.assertTrue(report.gzalloc.kind.startswith("use-after-free"))
        self.assertEqual(report.kernel_slide, 0x38F7C000)
        self.assertEqual(report.kernel_text_base, 0xFFFFFE003FF80000)
        self.assertEqual(report.kernel_text_exec_base, 0xFFFFFE0040A2C000)
        self.assertEqual(len(report.backtrace), 4)
        self.assertEqual(report.user_frames, [0x23DBAECD4])
        self.assertEqual(report.kernel_flavor, "RELEASE_ARM64_VRESEARCH1")
        self.assertEqual(report.evidence_level, "VM-observed")

    def test_parses_physical_shaped_report(self) -> None:
        report = probe.parse_panic_report(self.physical_report)
        self.assertEqual(report.panic_kind,
                         "Unexpected fault in kernel physical aperture")
        self.assertEqual(report.panicked_pid, 683)
        self.assertEqual(report.panicked_process, "Cyanide")
        self.assertIsNone(report.gzalloc)
        self.assertEqual(report.esr, 0x96000007)
        self.assertEqual(report.kernel_flavor, "RELEASE_ARM64_T8140")
        self.assertEqual(report.evidence_level, "physical-observed")
        self.assertEqual(len(report.backtrace), 2)

    def test_rejects_non_ips_input(self) -> None:
        broken = self.directory / "broken.ips"
        broken.write_text("not json")
        with self.assertRaises(probe.ProbeError):
            probe.parse_panic_report(broken)

    # --- classifier -------------------------------------------------------

    def test_vm_reference_matches_signature(self) -> None:
        result = probe.classify(probe.parse_panic_report(self.vm_report))
        self.assertTrue(result["matchesVMSignature"])
        detail = result["signatureDetail"]
        self.assertTrue(all(detail[key] for key in (
            "gzallocZone", "gzallocKind", "panicKind", "esr", "copyLength",
            "farInsideGZAllocElement", "labProviderProcess",
        )))
        self.assertEqual(result["evidenceLevel"], "VM-observed")
        self.assertEqual(result["copyLength"], "0x18")

    def test_physical_aperture_panic_does_not_match_signature(self) -> None:
        result = probe.classify(probe.parse_panic_report(self.physical_report))
        self.assertFalse(result["matchesVMSignature"])
        self.assertFalse(result["signatureDetail"]["gzallocZone"])
        self.assertFalse(result["signatureDetail"]["labProviderProcess"])
        self.assertEqual(result["evidenceLevel"], "physical-observed")
        self.assertIsNone(result["gzalloc"])

    def test_routes_resolve_absolute_and_text_base_offsets(self) -> None:
        report = probe.parse_panic_report(self.vm_report)
        routes = (
            ("absolute-hit", 0xFFFFFE0040BC5E78),
            ("offset-hit", 0xFFFFFE0040BC5E78 - 0xFFFFFE003FF80000),
            ("offset-miss", 0x7A59288),
        )
        hits = probe.classify(report, routes)["routeHits"]
        self.assertTrue(hits["absolute-hit"]["inBacktrace"])
        self.assertTrue(hits["offset-hit"]["inBacktrace"])
        self.assertEqual(hits["offset-hit"]["resolved"], "0xfffffe0040bc5e78")
        self.assertFalse(hits["offset-miss"]["inBacktrace"])
        self.assertEqual(hits["offset-miss"]["resolved"], "0xfffffe00479d9288")

    def test_route_argument_syntax_is_strict(self) -> None:
        self.assertEqual(probe.parse_route("NOOP=0x7a59288"), ("NOOP", 0x7A59288))
        for bad in ("NOOP", "NOOP=7a59288", "NOOP=0x", "bad name=0x1", "N=0x1;rm"):
            with self.assertRaises(probe.ProbeError):
                probe.parse_route(bad)

    def test_summary_lists_only_matching_reports(self) -> None:
        results = probe.classify_files([self.vm_report, self.physical_report], ())
        summary = probe.summarize(results)
        self.assertEqual(summary["reports"], 2)
        self.assertEqual(summary["matchingVMSignature"], [str(self.vm_report)])
        self.assertEqual(summary["evidenceLevels"],
                         ["VM-observed", "physical-observed"])

    # --- device gate --------------------------------------------------------

    def _details(self, identifier: str, product: str, build: str) -> dict:
        return {"result": {
            "identifier": identifier,
            "hardwareProperties": {"productType": product},
            "deviceProperties": {
                "osVersionNumber": "26.0", "osBuildUpdate": build,
                "name": "iPinky Max",
            },
        }}

    def test_device_identity_accepts_only_the_pinned_phone(self) -> None:
        good = self._details(probe.PHYSICAL_DEVICE_ID, "iPhone17,2", "23A341")
        identity = probe.verify_device_identity(good)
        self.assertEqual(identity["productType"], "iPhone17,2")
        self.assertEqual(identity["osBuildUpdate"], "23A341")

    def test_device_identity_refuses_the_vm_entry(self) -> None:
        vm = self._details("1039B523-F627-5381-B332-06A443B0547A", "iPhone99,11", "23A341")
        with self.assertRaisesRegex(probe.ProbeError, "research VM"):
            probe.verify_device_identity(vm)

    def test_device_identity_refuses_wrong_id_build_or_product(self) -> None:
        for identifier, product, build in (
            ("00000000-0000-0000-0000-000000000000", "iPhone17,2", "23A341"),
            (probe.PHYSICAL_DEVICE_ID, "iPhone17,2", "23B5001"),
            (probe.PHYSICAL_DEVICE_ID, "iPhone17,1", "23A341"),
        ):
            with self.assertRaises(probe.ProbeError):
                probe.verify_device_identity(self._details(identifier, product, build))

    def test_inventory_selects_only_top_level_panic_full_reports(self) -> None:
        root = {"result": {"files": [
            {"relativePath": "panic-full-2026-10-12-113515.0002.ips",
             "metadata": {"lastModDate": "2026-10-12T15:35:47.000Z", "size": 10}},
            {"relativePath": "JetsamEvent-2026-10-15-150022.ips",
             "metadata": {"lastModDate": "2026-10-15T19:00:29.000Z", "size": 20}},
            {"relativePath": "Retired/panic-full-2026-09-01-000000.0002.ips",
             "metadata": {"lastModDate": "2026-09-01T00:00:00.000Z", "size": 30}},
            {"relativePath": "panic-full-2026-10-07-203100.0002.ips",
             "metadata": {"lastModDate": "2026-10-08T00:31:35.000Z", "size": 40}},
        ]}}
        rows = probe.panic_reports_from_inventory(root)
        self.assertEqual([row[2] for row in rows], [
            "panic-full-2026-10-12-113515.0002.ips",
            "panic-full-2026-10-07-203100.0002.ips",
        ])

    def test_copy_refuses_non_panic_paths(self) -> None:
        for bad in ("../etc/passwd", "Cyanide-2026-10-07.ips",
                    "panic-full-2026-10-12-113515.0002.ips/x"):
            with self.assertRaises(probe.ProbeError):
                probe.device_copy_report("dev", bad, self.directory / "out")

    def test_capture_dir_is_never_reused(self) -> None:
        first = probe.fresh_capture_dir(self.directory, "stamp")
        self.assertTrue(first.is_dir())
        with self.assertRaises(probe.ProbeError):
            probe.fresh_capture_dir(self.directory, "stamp")

    def test_resume_requires_a_probe_capture_directory(self) -> None:
        with self.assertRaises(probe.ProbeError):
            probe.resumable_capture_dir(self.directory)
        capture = probe.fresh_capture_dir(self.directory, "resume")
        with self.assertRaises(probe.ProbeError):
            probe.resumable_capture_dir(capture)
        (capture / "crash-files.json").write_text("{}")
        self.assertEqual(probe.resumable_capture_dir(capture), capture)

    def test_copy_failures_are_recorded_and_existing_reports_are_kept(self) -> None:
        self.assertIn("copy_failures[relative] = str(error)", self.source)
        self.assertIn("if not destination.is_file():", self.source)
        self.assertIn('"copyFailures": copy_failures', self.source)
        self.assertIn('"complete": args.copy and not copy_failures', self.source)

    # --- guardrail pins -----------------------------------------------------

    def test_probe_is_read_only_and_never_reaches_the_lab_provider(self) -> None:
        # The module docstring explains why the provider cannot run on the
        # phone and may name its mechanisms; the code below it must not.
        code = self.source.split('"""', 2)[2]
        verbs = set(re.findall(
            r'"xcrun", "devicectl", "device", "([a-z]+)", "([a-z]+)"', code))
        self.assertEqual(verbs, {("info", "details"), ("info", "files"),
                                 ("copy", "from")})
        for forbidden in (
            "import cnd_vphone_krw", "import cnd_remotecall_lab", "from cnd_",
            "copy_binary", "start_provider", "codesign", "clang",
            "device install", "process launch", "ssh",
            "CNDLabKRWOperation", "kernel_call", "kread", "kwrite",
            "task_for_pid(", "libkrw-tfp0",
        ):
            self.assertNotIn(forbidden, code, forbidden)
        for required in (
            '"installedAnything": False', '"launchedAnything": False',
            '"kernelReadUsed": False', '"kernelWriteUsed": False',
            '"kernelCallUsed": False', '"labProviderContacted": False',
        ):
            self.assertIn(required, self.source, required)

    def test_vm_provider_flow_remains_vphone_gated(self) -> None:
        # The provider/harness that panicked the VM must stay unable to target
        # the phone: live harness actions require a VPHONE/VRESEARCH guest.
        gate = self.vm_harness.index("require_vphone(ssh)")
        self.assertLess(gate, self.vm_harness.index("copy_binary(\n"))
        self.assertLess(gate, self.vm_harness.index("start_provider(\n"))
        self.assertIn('lines[0].startswith("VPHONE")', self.vm_lab)
        self.assertIn('"VRESEARCH" not in lines[1]', self.vm_lab)
        self.assertIn("Physical-device KRW never routes through this API.",
                      self.provider_header)
        self.assertIn(
            "Never broaden the VM syscall-439 backend into a physical-device claim.",
            self.vm_guide,
        )

    def test_real_vm_reference_report_when_present(self) -> None:
        reference = ROOT / probe.VM_REFERENCE_SIGNATURE.reference_report
        if not reference.is_file():
            self.skipTest("VM reference panic report is not checked out")
        result = probe.classify(probe.parse_panic_report(reference))
        self.assertTrue(result["matchesVMSignature"])
        self.assertEqual(result["panickedPID"], 591)
        self.assertEqual(result["product"], "iPhone99,11")
        self.assertEqual(result["evidenceLevel"], "VM-observed")
        self.assertEqual(result["copyLength"], "0x18")


if __name__ == "__main__":
    unittest.main()
