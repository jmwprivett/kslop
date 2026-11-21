#!/usr/bin/env python3
"""Tests for the in-app physical kcall1 probe.

The probe (Cyanide/probes/CNDPhysicalKCall1Probe.{h,m}) is the phone path: it runs
the producer's chosen-PC/chosen-X0 canary in-process on the app's own
kexploit KRW and must never fall back to the provider socket, root, SSH, the
host-side harness or the VM syscall-439 backend.  These tests pin the
probe's hygiene, its seven phone route constants (against the derivation
module, not a copy), and the three borrowed stubs against the raw pinned
kernelcache bytes.
"""

from __future__ import annotations

import importlib
import re
import struct
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lab"))

SOURCE = ROOT / "Cyanide/probes/CNDPhysicalKCall1Probe.m"
HEADER = ROOT / "Cyanide/probes/CNDPhysicalKCall1Probe.h"
APP_DELEGATE = ROOT / "Cyanide/AppDelegate.m"
SETTINGS = ROOT / "Cyanide/SettingsViewController.m"

MODULE = importlib.import_module("cnd_physical_kcall1_krw")

# Probe static suffix -> the derivation module's phone value for that role.
ROLE_EXPECTATIONS: dict[str, int | None] = {
    "KernelBase": MODULE.PHONE_KERNELCACHE_CONTAINER_BASE,
    "FilesetEntry": MODULE.PHONE_KERNEL_FILESET_ENTRY_BASE,
    "CheckMultiGOT": MODULE.PHONE_ROUTE["checkmulti_got_donor"].address,
    "EtherCheckMulti": MODULE.PHONE_ROUTE["stock_callback"].address,
    "InitIfnetParams": MODULE.PHONE_ROUTE["init_ifnet_params"].address,
    "CheckMultiSigner": MODULE.PHONE_ROUTE["stock_signer"].address,
    "EnoexecReturn": MODULE.PHONE_ROUTE["enoexec_return_stub"].address,
    "LoadW0FromX0": MODULE.PHONE_ROUTE["load_w0_from_x0_stub"].address,
    "IfnetX0Dispatcher": MODULE.PHONE_ROUTE["ifnet_x0_dispatcher"].address,
}

PROBE_CONSTANT = re.compile(
    r"static const uint64_t CNDPhysicalKCall1Static(\w+) =\s*"
    r"UINT64_C\(0x([0-9A-Fa-f]{16})\);")


def probe_constants() -> dict[str, int]:
    source = SOURCE.read_text()
    return {
        suffix: int(value, 16)
        for suffix, value in PROBE_CONSTANT.findall(source)
    }


def probe_expected_words(name: str, count: int) -> list[int]:
    source = SOURCE.read_text()
    match = re.search(
        r"static const uint32_t CNDPhysicalKCall1Expected%s\[%d\] = \{"
        r"(.*?)\};" % (re.escape(name), count), source, re.S)
    if match is None:
        raise AssertionError(f"missing CNDPhysicalKCall1Expected{name}")
    words = re.findall(
        r"UINT32_C\(0x([0-9A-Fa-f]{8})\)", match.group(1))
    if len(words) != count:
        raise AssertionError(f"{name}: {len(words)} words, want {count}")
    return [int(word, 16) for word in words]


def kernel_segments() -> list[tuple[int, int, int, int]]:
    path = MODULE.PHONE_KERNEL_IMAGE
    if not path.exists():
        raise unittest.SkipTest(f"missing pinned kernelcache {path}")
    with path.open("rb") as handle:
        header = handle.read(0x40000)
    ncmds = struct.unpack_from("<I", header, 16)[0]
    offset = 32
    segments = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", header, offset)
        if cmd == 0x19:  # LC_SEGMENT_64
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                "<QQQQ", header, offset + 24)
            segments.append((vmaddr, vmsize, fileoff, filesize))
        offset += cmdsize
    return segments


def kernel_words(vaddr: int, count: int) -> list[int]:
    path = MODULE.PHONE_KERNEL_IMAGE
    for vmaddr, vmsize, fileoff, filesize in kernel_segments():
        if (vmsize and fileoff and filesize and vmaddr <= vaddr and
                vaddr + count * 4 <= vmaddr + vmsize and
                vaddr + count * 4 <= vmaddr + filesize):
            with path.open("rb") as handle:
                handle.seek(fileoff + (vaddr - vmaddr))
                return list(struct.unpack(
                    "<%dI" % count, handle.read(count * 4)))
    raise AssertionError(f"{vaddr:#x} is not mapped in the phone image")


class PhysicalKCall1ProbeTests(unittest.TestCase):
    def test_probe_uses_the_app_krw_and_no_provider_root_or_kcall(
            self) -> None:
        source = SOURCE.read_text()
        # The app's own kernel read/write primitives and base source.
        self.assertIn('"kreadbuf"', source)
        self.assertIn('"kwrite64"', source)
        self.assertIn('"kexploit_early_kwrite32bytes_checked"', source)
        self.assertIn('"kexploit_krw_ready"', source)
        self.assertIn('"g_kernel_base"', source)
        self.assertIn('"g_kernel_slide"', source)
        # No VM syscall-439 backend: not resolved by name and never called.
        # (The probe may *name* it in a doc comment explaining the exclusion,
        # so pin the dlsym string and the call form instead of the word.)
        self.assertNotIn('"cnd_lab_kernel_call"', source,
                         "the probe must not resolve the VM kcall backend")
        self.assertNotIn("cnd_lab_kernel_call(", source,
                         "the probe must not call the VM kcall backend")
        self.assertNotIn("kernel_call(", source.lower(),
                         "the probe must not call any kernel_call primitive")
        self.assertNotIn("CNDLabKRWOperation", source,
                         "the probe must not speak the provider protocol")
        self.assertNotIn("CNDConnectProvider", source,
                         "the probe must not connect to the provider")
        self.assertNotIn("sockaddr_un", source,
                         "the probe must not open a unix socket")
        self.assertNotIn("AF_UNIX", source,
                         "the probe must not open a unix socket")
        self.assertNotIn("pgrep", source,
                         "the probe must not look up the donor by shelling out")
        self.assertNotIn("cnd_iouserethernet_krw_trigger.py", source,
                         "the probe must not depend on the host harness")

    def test_probe_uses_the_app_helpers_not_vm_offset_walks(self) -> None:
        source = SOURCE.read_text()
        # Processes come from the app's own offset table ...
        self.assertIn('"proc_find_by_name"', source)
        self.assertIn('"proc_self"', source)
        self.assertIn('"proc_get_cred_label"', source)
        # ... and Mach ports from its IPC-object helper, not a hand walk.
        self.assertIn('"task_get_ipc_port_kobject"', source)
        self.assertNotIn("allproc", source.lower())
        self.assertNotIn("0x57d", source)
        self.assertNotIn("0x310", source)

    def test_probe_initializes_offsets_before_the_slot_preflight(self) -> None:
        source = SOURCE.read_text()
        # The slot offsets only exist after offsets.m has run, and
        # offsets_init() is called from inside the exploit
        # (kexploit_opa334.m:3121) or persistence.m:640 - not at process start.
        # A headless launch therefore read zeroes and refused; the audit probe
        # carried the identical trap and hit it on device 2026-10-18.
        self.assertIn('CND_KCALL1_RESOLVE(offsetsInit, "offsets_init")',
                      source)
        self.assertLess(source.index("kernel.offsetsInit();"),
                        source.index('@"refused-label-slot-mismatch"'))
        self.assertIn('report[@"offsetsInitCalled"] = @YES;', source)
        self.assertIn("kexploit_opa334.m:3121", source)

    def test_probe_route_constants_agree_with_the_derivation(self) -> None:
        constants = probe_constants()
        self.assertEqual(
            sorted(constants), sorted(ROLE_EXPECTATIONS),
            "the probe must carry exactly the derived phone statics")
        for suffix, expected in ROLE_EXPECTATIONS.items():
            self.assertIsNotNone(
                expected,
                f"{suffix} is an unresolved route role in the derivation")
            self.assertEqual(
                constants[suffix], expected,
                f"{suffix} disagrees with the derivation module")

    def test_probe_constants_are_phone_space_and_never_vm_space(self) -> None:
        # Every route static must land in the phone kernel window that the
        # producer's phone layout uses, never in the vPhone window.
        for suffix, value in probe_constants().items():
            self.assertGreaterEqual(
                value, 0xFFFFFFF000000000,
                f"{suffix} is below the phone kernel window")
            self.assertLess(
                value, 0xFFFFFFFF00000000,
                f"{suffix} is above the phone kernel window")
        source = SOURCE.read_text().lower()
        # The only 0xfffffe prefix allowed is the architectural virtual
        # window bound; no vPhone kernel-text address may appear.
        self.assertNotIn("0xfffffe0008", source,
                         "a vPhone kernel-text address leaked into the probe")
        self.assertNotIn("0xfffffe0007", source,
                         "a vPhone kernel-text address leaked into the probe")

    def test_probe_load_stub_pin_is_the_reconciled_element(self) -> None:
        source = SOURCE.read_text()
        self.assertIn("CNDPhysicalKCall1StaticLoadW0FromX0 =\n"
                      "    UINT64_C(0xfffffff008a4b130);", source)
        # The shape-only second claimant of the ambiguity is never used.
        self.assertNotIn("0xfffffff00826a470", source)

    def test_probe_expected_stubs_are_the_pinned_kernelcache_bytes(
            self) -> None:
        stubs = (
            ("Enoexec", ROLE_EXPECTATIONS["EnoexecReturn"], 3),
            ("Load", ROLE_EXPECTATIONS["LoadW0FromX0"], 3),
            ("Dispatcher", ROLE_EXPECTATIONS["IfnetX0Dispatcher"], 7),
        )
        for name, address, count in stubs:
            assert address is not None
            self.assertEqual(
                probe_expected_words(name, count),
                kernel_words(address, count),
                f"{name} does not match the pinned phone image")
        # The two vacuous stubs are the two nop/ret pairs the producer
        # compares, not arbitrary words.
        self.assertEqual(
            probe_expected_words("Enoexec", 3),
            [0xD503245F, 0x52800100, 0xD65F03C0])
        self.assertEqual(
            probe_expected_words("Load", 3),
            [0xD503245F, 0xB9400000, 0xD65F03C0])
        self.assertEqual(
            probe_expected_words("Dispatcher", 7),
            [0xD503245F, 0xF9405810, 0xB4000090, 0xF9404800,
             0xD29C9FD1, 0xD71F0A11, 0xD65F03C0])

    def test_probe_borrows_both_gate_policies(self) -> None:
        source = SOURCE.read_text()
        self.assertIn('"off_label_l_perpolicy_amfi"', source)
        self.assertIn('"off_label_l_perpolicy_sandbox"', source)
        self.assertIn("donorAMFIObject", source)
        self.assertIn("donorSandboxObject", source)
        self.assertIn("CNDPhysicalKCall1LabelSize = 0x20", source)
        self.assertIn('"amfi_cslot_get"', source)
        self.assertIn('"label_get_sandbox"', source)

    def test_probe_restores_the_label_before_any_selector(self) -> None:
        source = SOURCE.read_text()
        run_once = source[source.index("CNDPhysicalKCall1RunOnce"):]
        restore = run_once.index(
            "bool restored = CNDPhysicalKCall1RestoreBorrow(&kernel, "
            "&borrow);")
        selector = run_once.index("CNDPhysicalKCall1RunCanary(")
        self.assertLess(restore, selector)
        self.assertIn('report[@"selectorInvokedAfterRestore"] = @YES;',
                      source)
        self.assertIn('report[@"restoreWholeLabelExact"] = @(restored);',
                      source)

    def test_probe_resolves_labels_after_the_negative_baseline(self) -> None:
        source = SOURCE.read_text()
        baseline = source.index('report[@"baselineOpenKR"]')
        labels = source.index('report[@"labelResolvedAfterBaseline"]')
        self.assertLess(baseline, labels)
        self.assertIn("baseline-unexpectedly-authorized", source)

    def test_probe_gates_the_exact_phone(self) -> None:
        source = SOURCE.read_text()
        self.assertIn('"iPhone17,2"', source)
        self.assertIn('"23A341"', source)
        self.assertIn('sysctlbyname(name, value, &size, NULL, 0)', source)
        self.assertIn("refused-unsupported-device", source)

    def test_probe_verifies_the_base_is_the_pinned_kernel_image(self) -> None:
        source = SOURCE.read_text()
        self.assertIn("#include <mach-o/loader.h>", source)
        self.assertIn("MH_MAGIC_64", source)
        self.assertIn("MH_FILESET", source)
        self.assertIn("refused-kernel-header", source)
        self.assertIn("refused-base-mismatch", source)
        self.assertIn('"g_kernel_slide"', source)

    def test_probe_arms_the_canary_and_reports_the_verdict(self) -> None:
        source = SOURCE.read_text()
        # The chosen-PC/chosen-X0 chain and its EINPROGRESS marker.
        self.assertIn("(uint64_t)EINPROGRESS", source)
        self.assertIn("ifnetKCall1Success", source)
        self.assertIn('report[@"ifnetKCall1ConstructedArity"] = @1;', source)
        self.assertIn('report[@"ifnetKCall1ProviderKCallUsed"] = @NO;',
                      source)
        self.assertIn("CNDPhysicalKCall1TriggerIfnetCheckMulti", source)
        self.assertIn("SIOCADDMULTI", source)
        self.assertIn("criticalRestoreFailure", source)
        # A PAC-signed or plain stock GOT pointer both strip to the stock
        # target; the probe records which form it found.
        self.assertIn('report[@"ifnetPACGOTOriginalForm"]', source)
        # The verdict names exactly where a failed run stopped.
        self.assertIn('@"physical-krw-kcall1-chosen-pc-chosen-x0"', source)
        self.assertIn('@"canary-setup-refused"', source)
        self.assertIn('@"canary-stage-refused"', source)
        self.assertIn('@"trigger-failed"', source)

    def test_probe_never_scans_or_brute_forces_kernel_memory(self) -> None:
        source = SOURCE.read_text()
        for pattern in ("for (uint64_t address", "for (uint64_t candidate",
                        "strtoull", "scanf"):
            self.assertNotIn(pattern, source)
        # Every route static is a literal; nothing is computed from a scan.
        self.assertEqual(len(probe_constants()), len(ROLE_EXPECTATIONS))

    def test_header_declares_the_probe_api(self) -> None:
        header = HEADER.read_text()
        self.assertIn("CNDPhysicalKCall1ProbeRun", header)
        self.assertIn("CNDPhysicalKCall1ProbeIsSupported", header)
        self.assertIn("CNDPhysicalKCall1ProbeIsRunning", header)

    def test_launch_argument_also_runs_the_probe(self) -> None:
        source = APP_DELEGATE.read_text()
        self.assertIn('--kcall1-probe', source)
        self.assertIn("CNDPhysicalKCall1ProbeRun", source)
        self.assertIn('"probes/CNDPhysicalKCall1Probe.h"', source)

    def test_probe_diagnoses_a_refused_label_write(self) -> None:
        source = SOURCE.read_text()
        # The socket writer returns only a bool, and it also returns false
        # when its post-write park fails even though the bytes landed.  A
        # refused borrow must therefore read the label back and report what
        # actually happened rather than only "false".
        for key in (
            'report[@"labelWriteAccepted"]',
            'report[@"labelWriteErrno"]',
            'report[@"labelChangedAfterWrite"]',
            'report[@"labelMatchesDesiredAfterWrite"]',
            'report[@"labelAfterWriteCaptured"]',
            'report[@"labelBytesBeforeWrite"]',
            'report[@"labelBytesAfterWrite"]',
        ):
            self.assertIn(key, source)
        accepted = source.index("bool accepted = api->write32BytesChecked(")
        readback = source.index(
            "bool captured = CNDPhysicalKCall1ReadLabel(api, label, observed);"
        )
        self.assertLess(accepted, readback)

    def test_settings_exposes_the_probe_in_a_dedicated_probes_section(self) -> None:
        settings = SETTINGS.read_text()
        # Its own root section: the Quick Actions row count is a deliberate
        # pin that keeps the Hail Mary / icon-redirect diagnostics retained
        # but unexposed, so the probe row must not widen that section. The
        # section's own fourth row is the read-only .34 page-wire probe.
        self.assertRegex(settings, r"case RootSectionProbes:\s+return 17;")
        self.assertRegex(settings, r'case RootSectionProbes:\s+return @"Probes";')
        self.assertIn("case RootSectionActions:        return 6;", settings)
        # Gated on the probe's own support check and routed through the
        # confirm alert + inline activity log, like the other probe rows.
        self.assertIn("CNDPhysicalKCall1ProbeIsSupported(&reason)", settings)
        self.assertIn("CNDPhysicalKCall1ProbeIsRunning()", settings)
        self.assertIn("CNDPhysicalKCall1ProbeRun(", settings)
        self.assertIn('"probes/CNDPhysicalKCall1Probe.h"', settings)
        self.assertIn("Run IOUserEthernet KCall1 Canary", settings)

    def test_finished_probe_does_not_read_as_still_running(self) -> None:
        source = SOURCE.read_text()
        # The flag is cleared and the run is over before completion fires, so
        # the report must not keep its last in-flight state on disk.
        run_once = source.index(
            "NSDictionary<NSString *, id> *report = CNDPhysicalKCall1RunOnce();")
        released = source.index(
            "__sync_lock_release(&gCNDPhysicalKCall1ProbeRunning);")
        terminal = source.index('@"state", @"finished"')
        self.assertLess(run_once, released)
        self.assertLess(released, terminal)

        # And the completion has to stop the Activity sheet's footer, which
        # only ends on the installer's completion notification, and rebuild the
        # row, whose title otherwise keeps reading "… Running…".
        settings = SETTINGS.read_text()
        self.assertIn("- (void)finishProbeActivityForRow:(NSInteger)row",
                      settings)
        self.assertIn("settings_post_actions_complete_async(", settings)
        self.assertIn('@"physical-krw-kcall1-chosen-pc-chosen-x0";', settings)
        self.assertRegex(
            settings,
            r"- \(void\)reloadProbeRows\s*\{[^}]*RootSectionProbes",
        )
        logged = settings.index('"[KCALL1] result=%s success=%s report=%s\\n"')
        finished = settings.index(
            "[strongSelf finishProbeActivityForRow:row", logged)
        self.assertLess(logged, finished)


if __name__ == "__main__":
    unittest.main()
