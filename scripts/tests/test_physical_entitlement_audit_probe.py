#!/usr/bin/env python3
"""Tests for the in-app read-only entitlement audit probe.

The probe (Cyanide/probes/CNDPhysicalEntitlementAuditProbe.{h,m}) exists to answer one
question the kernelcache cannot: whether the IOUserEthernet donor actually
carries `com.apple.networking.ethernet.user-access`, which is code-signature
data in userspace.  It is the read-only counterpart to the kcall1 / signer
probes - it must never write kernel memory, never borrow a MAC label and never
issue a kernel call, because the phone's socket writer refuses the MAC-label
object with EFAULT anyway.

These tests pin that hygiene, the device gate, the pointer-validation discipline
of the scan, and the scan's hard bounds.  They also tie the probe's needle and
its "entitlement missing" citation to the pinned 23A341 kext when that artifact
is present locally.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

SOURCE = ROOT / "Cyanide/probes/CNDPhysicalEntitlementAuditProbe.m"
HEADER = ROOT / "Cyanide/probes/CNDPhysicalEntitlementAuditProbe.h"
APP_DELEGATE = ROOT / "Cyanide/AppDelegate.m"
SETTINGS = ROOT / "Cyanide/SettingsViewController.m"

KEXT = (
    ROOT
    / "build/rea-secure-execution-23A341-iphone17,2"
    / "kernel-filesets-stock/com.apple.iokit.IOUserEthernet"
)

ENTITLEMENT = "com.apple.networking.ethernet.user-access"

DEFINE = re.compile(r"^#define (CND_[A-Z0-9_]+) (.+)$", re.MULTILINE)


def defines() -> dict[str, str]:
    return {name: value.strip() for name, value in DEFINE.findall(SOURCE.read_text())}


def numeric_define(name: str) -> int:
    value = defines()[name]
    match = re.search(r"0x([0-9A-Fa-f]+)|([0-9]+)", value)
    if match is None:
        raise AssertionError(f"{name} is not a numeric literal: {value}")
    if match.group(1) is not None:
        return int(match.group(1), 16)
    return int(match.group(2), 10)


class EntitlementAuditProbeTests(unittest.TestCase):
    def test_probe_is_strictly_read_only(self) -> None:
        source = SOURCE.read_text()
        # No write primitive of any kind may appear in this probe.
        for forbidden in (
            "kwrite64",
            "kwrite32",
            "kwrite8",
            "kwritebuf",
            "kexploit_early_kwrite32bytes_checked",
            "early_kwrite",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn('@"kernelWriteUsed": @NO', source)
        self.assertIn('@"kernelReadUsed": @YES', source)
        self.assertIn('@"kernelCallUsed": @NO', source)
        self.assertIn('@"providerUsed": @NO', source)
        self.assertIn('@"labelBorrowed": @NO', source)
        self.assertIn('@"operation": @"read-only-entitlement-audit"', source)

    def test_probe_never_uses_the_vm_backend_provider_or_root(self) -> None:
        source = SOURCE.read_text()
        for forbidden in (
            "cnd_lab_kernel_call",
            "cnd_lab_krw",
            "cnd_lab_krw_write",
            "syscall(439",
            "socket(",
            "system(",
            "popen(",
            "ssh",
            "pgrep",
        ):
            self.assertNotIn(forbidden, source)

    def test_probe_gates_on_the_exact_phone(self) -> None:
        source = SOURCE.read_text()
        self.assertIn('"iPhone17,2"', defines()[
            "CND_PHYSICAL_ENTITLEMENT_AUDIT_EXPECTED_PRODUCT"])
        self.assertIn('"23A341"', defines()[
            "CND_PHYSICAL_ENTITLEMENT_AUDIT_EXPECTED_BUILD"])
        self.assertIn('CNDPhysicalEntitlementAuditSysctlString("hw.machine")',
                      source)
        self.assertIn('CNDPhysicalEntitlementAuditSysctlString("kern.osversion")',
                      source)
        self.assertIn('@"refused-unsupported-device"', source)
        self.assertIn(
            "BOOL CNDPhysicalEntitlementAuditProbeIsSupported(NSString **reasonOut)",
            source)
        self.assertIn("BOOL CNDPhysicalEntitlementAuditProbeIsRunning(void)",
                      source)
        self.assertIn(
            "void CNDPhysicalEntitlementAuditProbeRun(\n"
            "    CNDPhysicalEntitlementAuditProbeCompletion completion)",
            source)

    def test_probe_audits_the_donor_first_then_the_fallbacks(self) -> None:
        source = SOURCE.read_text()
        match = re.search(
            r"CNDPhysicalEntitlementAuditCandidates\[\] = \{(.*?)\};",
            source, re.DOTALL)
        self.assertIsNotNone(match)
        names = re.findall(r'"([a-z0-9_.-]+)"', match.group(1))
        self.assertEqual(names[0], "bluetoothd")
        self.assertEqual(
            names[1:], ["configd", "nehelper", "symptomsd", "wifid"])
        # The donor verdict is reported separately from the raw per-process
        # fields, and bluetoothd is the one that decides it.
        self.assertIn('@"donorProcess": @"bluetoothd"', source)
        self.assertIn('@"donorHasEntitlement"', source)
        self.assertIn('strcmp(target.name, "bluetoothd") == 0', source)
        self.assertIn('@"processesWithEntitlement"', source)

    def test_probe_reads_the_amfi_slot_out_of_the_credential_label(self) -> None:
        source = SOURCE.read_text()
        self.assertIn(
            "CNDPhysicalEntitlementAuditAMFISlotOffset = 0x8,", source)
        self.assertIn(
            "CNDPhysicalEntitlementAuditSandboxSlotOffset = 0x10,", source)
        self.assertIn('CND_ENT_AUDIT_RESOLVE(procGetCredLabel, '
                      '"proc_get_cred_label")', source)
        self.assertIn('CND_ENT_AUDIT_RESOLVE(amfiSlotOffset, '
                      '"off_label_l_perpolicy_amfi")', source)
        self.assertIn('CND_ENT_AUDIT_RESOLVE(sandboxSlotOffset,\n'
                      '        "off_label_l_perpolicy_sandbox")', source)
        # The slot offsets are read from the app's own offsets module and must
        # still equal the contract before anything is followed.
        self.assertIn('@"refused-label-slot-mismatch"', source)
        self.assertIn(
            "CNDPhysicalEntitlementAuditAMFISlotOffset ||", source)

    def test_probe_initializes_offsets_before_the_slot_preflight(self) -> None:
        source = SOURCE.read_text()
        # The offsets the chain reads are published by offsets.m, and nothing
        # has run it this early: offsets_init() is called from inside the
        # exploit (kexploit_opa334.m:3121) or from persistence.m:640, not at
        # process start.  A headless launch therefore read zeroes and refused
        # (device run 2026-10-18: `refused-label-slot-mismatch`, both slot
        # offsets 0) - and the same zeroes would have been used as
        # proc/ucred/label offsets by the chain.
        self.assertIn('CND_ENT_AUDIT_RESOLVE(offsetsInit, "offsets_init")',
                      source)
        self.assertLess(source.index("kernel.offsetsInit();"),
                        source.index('@"refused-label-slot-mismatch"'))
        # Cheap, kernel-free (userland version + hw.cpufamily), and recorded so
        # a future run that proceeds says why it could.
        self.assertIn('report[@"offsetsInitCalled"] = @YES;', source)
        self.assertIn("kexploit_opa334.m:3121", source)
        self.assertIn("persistence.m:640", source)

    def test_probe_validates_every_hop_before_the_next(self) -> None:
        source = SOURCE.read_text()
        chain = source.split("static bool CNDPhysicalEntitlementAuditReadChain(",
                             1)[1]
        # Each hop value is window-checked before it becomes the next base.
        self.assertIn("CNDPhysicalEntitlementAuditKernelObject(scan->procRO)",
                      chain)
        self.assertIn("CNDPhysicalEntitlementAuditKernelObject(scan->ucredRaw)",
                      chain)
        self.assertIn("CNDPhysicalEntitlementAuditKernelObject(scan->roObject)",
                      chain)
        self.assertIn(
            "CNDPhysicalEntitlementAuditKernelObject(scan->amfiSlotValue)",
            chain)
        # The four chain offsets come from the app's own offsets module (the
        # same values kutils.m uses), not from constants in this file.
        for symbol in ("off_proc_p_proc_ro", "off_proc_ro_p_ucred",
                       "off_ucred_cr_label", "off_label_l_perpolicy_amfi"):
            self.assertIn(f'"{symbol}"', source)
        # Both PAC strips are still offered, and the SMR decoder is consulted
        # because the header declares p_ucred an SMR pointer.
        self.assertIn("dac147e0", source)  # xpacd
        self.assertIn("dac143e0", source)  # xpaci
        self.assertIn('"kread_smrptr"', source)
        # The label hop is a self-check against the app's device-proven path,
        # and it accepts the xpaci decode that kutils itself uses (kread_ptr,
        # krw.m:145) rather than only the data strip.
        self.assertIn("scan->labelMatchesKutils =", chain)
        self.assertIn("scan->labelInstrStrip == target->label", chain)
        self.assertIn("scan->labelDataStrip == target->label", chain)
        self.assertIn("krw.m:145", source)
        self.assertIn('"label-chain-mismatch"', source)

    def test_probe_typed_read_bounds_are_hard_caps(self) -> None:
        source = SOURCE.read_text()
        cap = numeric_define("CND_ENT_AUDIT_DER_CAP")
        budget = numeric_define("CND_ENT_AUDIT_READ_BUDGET")
        self.assertLessEqual(cap, 0x10000)
        self.assertLessEqual(budget, 100000)
        self.assertIn("scan->reads + 1 > CND_ENT_AUDIT_READ_BUDGET", source)
        self.assertIn("scan->truncated = true;", source)
        # The DER blob is streamed, never window-read: a wider transfer can
        # cross the blob's zone element boundary and fault the kernel.
        self.assertIn("CNDPhysicalEntitlementAuditReadDER", source)
        self.assertIn("CNDPhysicalEntitlementAuditChainReadU64", source)
        self.assertIn(
            "scan->derEnd - scan->derStart > CND_ENT_AUDIT_DER_CAP", source)
        self.assertIn(
            'report[@"readGranularityBytes"] = @(sizeof(uint64_t));', source)
        # The one window read left is the label, whose object is big enough.
        self.assertIn('@"label-window"', source)
        # A truncated stream must not read as "no entitlement".
        self.assertIn('entry[@"scanTruncated"] = @(target->scan.truncated);',
                      source)

    def test_probe_bands_the_der_pair_instead_of_demanding_alignment(
            self) -> None:
        source = SOURCE.read_text()
        # The device's own AMFI image shows ro+0x38/ro+0x40 are the DER
        # decoder's begin/end byte pointers (0xfffffff00977e43c writes them at
        # ctx+0x8+0x28/+0x30 and enforces only begin <= end, `cmp x9, x8;
        # b.hi` -> brk, 0xfffffff00977e48c).  A byte range is not 8-aligned, so
        # the range gate must band-test it; the aligned object test would have
        # refused all four 2026-10-18 candidates, which held in-band, ordered
        # ranges of 1922..7920 bytes.
        self.assertIn("CNDPhysicalEntitlementAuditObjectBand(scan->derStart)",
                      source)
        self.assertIn("CNDPhysicalEntitlementAuditObjectBand(scan->derEnd)",
                      source)
        self.assertNotIn(
            "CNDPhysicalEntitlementAuditKernelObject(scan->derStart)", source)
        # The aligned test still composes the band test for real objects.
        body = source.split(
            "static bool CNDPhysicalEntitlementAuditKernelObject(", 1)[1]
        body = body.split("}", 1)[0]
        self.assertIn("CNDPhysicalEntitlementAuditObjectBand(value)", body)
        self.assertIn("(value & UINT64_C(0x7)) == 0", body)
        # The offsets are cited from the image, not asserted.
        for citation in ("0xfffffff00977674c", "0xfffffff009770100",
                         "0xfffffff00977e43c", "0xfffffff00977e48c"):
            self.assertIn(citation, source)
        self.assertIn("carries no alignment requirement", source)
        # The decoded item's type word is captured before the gate, so an
        # aborted range still carries structural corroboration.
        self.assertIn("CND_ENT_AUDIT_OSENTITLEMENTS_DER_TYPE_OFFSET", source)
        self.assertIn('entry[@"derItemTypeWord"]', source)
        self.assertIn('entry[@"derItemTypeWordExpected"]', source)
        gate = source.index('"der-range-invalid"')
        self.assertLess(source.index('entry[@"derItemTypeWord"]'), gate)
        self.assertLess(source.index("&scan->derStart"), gate)

    def test_probe_records_chain_evidence_not_only_a_verdict(self) -> None:
        source = SOURCE.read_text()
        # Sample `com.apple.` strings make entitlementFound=false meaningful
        # rather than the result of a chain that never reached entitlement data.
        self.assertIn('static const char prefix[] = "com.apple.";', source)
        self.assertIn('entry[@"sampleStrings"] = samples;', source)
        for field in ("procRO", "ucred", "labelMatchesKutils", "roObject",
                      "roOwnerCheck", "roContextCheck", "derStart", "derEnd",
                      "derLength", "derBytesRead", "derKeyOffset",
                      "entitlementValueHex", "chainAborted", "scanReads"):
            self.assertIn(f'entry[@"{field}"]', source)
        self.assertIn('@"labelBytes"', source)

    def test_probe_reports_its_own_schema_and_verdict(self) -> None:
        source = SOURCE.read_text()
        self.assertIn(
            '@"schema": @"com.zeroxjf.cyanide.physical-entitlement-audit"',
            source)
        self.assertIn('@"schemaVersion": @2', source)
        self.assertIn('@"CNDPhysicalEntitlementAuditProbe.json"', source)
        for verdict in (
            "refused-api-unavailable",
            "refused-krw-not-ready",
            "refused-base-mismatch",
            "refused-kernel-header",
            "refused-no-process-resolved",
            "physical-krw-entitlement-audit-complete",
        ):
            self.assertIn(f'@"{verdict}"', source)

    def test_probe_confirms_the_base_before_trusting_reads(self) -> None:
        source = SOURCE.read_text()
        self.assertIn("UINT64_C(0xfffffff007004000)", source)
        self.assertIn("MH_MAGIC_64", source)
        self.assertIn("MH_FILESET", source)
        self.assertIn('@"kernelBaseMatchesContainer"', source)

    def test_header_declares_the_same_three_entry_points(self) -> None:
        header = HEADER.read_text()
        self.assertIn("CNDPhysicalEntitlementAuditProbeCompletion", header)
        self.assertIn(
            "BOOL CNDPhysicalEntitlementAuditProbeIsSupported(NSString **reasonOut);",
            header)
        self.assertIn("BOOL CNDPhysicalEntitlementAuditProbeIsRunning(void);",
                      header)
        self.assertIn("void CNDPhysicalEntitlementAuditProbeRun(", header)
        self.assertIn("Read-only audit", header)
        self.assertIn("never writes kernel memory", header)

    def test_launch_argument_also_runs_the_probe(self) -> None:
        source = APP_DELEGATE.read_text()
        self.assertIn('--entitlement-audit-probe', source)
        self.assertIn("CNDPhysicalEntitlementAuditProbeRun", source)
        self.assertIn('"probes/CNDPhysicalEntitlementAuditProbe.h"', source)

    def test_settings_exposes_the_audit_row_in_the_probes_section(self) -> None:
        settings = SETTINGS.read_text()
        # Row three of the same dedicated section; the fourth row is the
        # read-only Hail Mary .34 page-wire probe. Quick Actions stays pinned
        # so the retained-but-unexposed diagnostics cannot ride along.
        self.assertRegex(settings, r"case RootSectionProbes:\s+return 17;")
        self.assertIn("case RootSectionActions:        return 6;", settings)
        self.assertIn("CNDPhysicalEntitlementAuditProbeIsSupported(&reason)",
                      settings)
        self.assertIn("CNDPhysicalEntitlementAuditProbeIsRunning()", settings)
        self.assertIn("CNDPhysicalEntitlementAuditProbeRun(", settings)
        self.assertIn("Audit IOUserEthernet Entitlement", settings)
        # Its confirm text must state that it is read-only.
        self.assertIn(
            "Nothing is written, no label is borrowed, and no kernel call is "
            "issued.", settings)
        # The two existing rows keep their own wiring.
        self.assertIn("CNDPhysicalKCall1ProbeRun(", settings)
        self.assertIn("CNDPhysicalIOUserEthernetSignerProbeRun(", settings)

    def test_probe_has_no_window_walk_left(self) -> None:
        source = SOURCE.read_text()
        # The retired walk, in every part: windows, depth cap, visited set,
        # recursion and its node counter.
        for gone in ("CND_ENT_AUDIT_SHALLOW_WINDOW",
                     "CND_ENT_AUDIT_DEEP_WINDOW",
                     "CND_ENT_AUDIT_SHALLOW_DEPTH",
                     "CND_ENT_AUDIT_MAX_DEPTH",
                     "CND_ENT_AUDIT_VISITED",
                     "CNDPhysicalEntitlementAuditWalk",
                     "CNDPhysicalEntitlementAuditScanGraph",
                     "CNDPhysicalEntitlementAuditTargetReport",
                     "scanNodes"):
            self.assertNotIn(gone, source)
        self.assertIn('report[@"windowWalkUsed"] = @NO;', source)
        self.assertIn('report[@"chainType"] = @"typed-windowless-read";', source)

    def test_probe_persists_the_next_address_before_reading_it(self) -> None:
        source = SOURCE.read_text()
        self.assertIn('entry[@"nextReadAddress"] =', source)
        # Every hop names its stage, and the address it is about to read, before
        # the read happens - so a faulting run leaves an attributable trail.
        for stage in ("proc-ro", "ucred", "label", "osentitlements-ro",
                      "der-range", "der-stream"):
            self.assertIn(f'@"{stage}"', source)
        self.assertIn("CNDPhysicalEntitlementAuditTrail(report, reportPath, "
                      "entry", source)

    def test_probe_aborts_instead_of_reporting_a_negative(self) -> None:
        source = SOURCE.read_text()
        for reason in ("proc-ro-not-object", "ucred-not-object",
                       "label-chain-mismatch", "amfi-slot-not-object",
                       "ro-owner-mismatch", "ro-context-mismatch",
                       "der-range-invalid"):
            self.assertIn(f'"{reason}"', source)
        self.assertIn("scan->aborted = true;", source)
        # The AMFI read-only checks gate the DER read: no DER byte is read
        # unless both self-referential fields hold.
        chain = source.split("static bool CNDPhysicalEntitlementAuditReadChain(",
                             1)[1]
        gate = chain.index("if (!scan->roOwnerCheck || !scan->roContextCheck)")
        der = chain.index("&scan->derStart")
        self.assertLess(gate, der)
        # An aborted chain is never counted as a holder or a stem holder.
        self.assertIn("!target.scan.aborted && target.scan.found", source)
        self.assertIn("!target.scan.aborted && target.scan.stemFound", source)
        # A run where no candidate reached a verdict says so, instead of letting
        # donorHasEntitlement=NO read as an answer to the donor question.
        self.assertIn('@"physical-krw-entitlement-audit-aborted"', source)
        self.assertIn('@"donorAuditVerdictReached"', source)
        self.assertIn("verdicts > 0 ?", source)
        # Reads are range-gated by the app's own checked KRW path; the residual
        # hazard is an in-range unmapped address, which is what the hops' own
        # structural checks are for.
        self.assertIn("early_kread64_checked", source)
        self.assertIn("is_kaddr_valid", source)

    def test_probe_documents_the_panics_it_caused(self) -> None:
        source = SOURCE.read_text()
        panic_doc = (ROOT / "docs/research"
                     / "entitlement-audit-panic-20261018-iphone17,2.md")
        design_doc = (ROOT / "docs/research"
                      / "entitlement-audit-typed-read-design-20261018.md")
        self.assertTrue(panic_doc.exists())
        self.assertTrue(design_doc.exists())
        self.assertIn("entitlement-audit-panic-20261018-iphone17,2.md", source)
        self.assertIn("entitlement-audit-typed-read-design-20261018.md", source)
        # The false claim is refuted in place: an unmapped or aperture read does
        # not come back as zeroes, it faults the kernel - which is what those
        # panics are.  The old "rather than faulting" reassurance is gone.
        self.assertIn("was wrong", source)
        self.assertNotIn("rather than faulting", source)
        self.assertIn("was wrong: they fault", source)

    @unittest.skipUnless(KEXT.exists(), "pinned 23A341 IOUserEthernet kext absent")
    def test_probe_cites_the_device_derivation_for_each_amfi_offset(self) -> None:
        source = SOURCE.read_text()
        # Two chain offsets are read straight out of the device's own AMFI image
        # (same kernelcache UUID as the phone), so a reader can re-derive them
        # instead of trusting a constant.
        amfi = ("build/rea-secure-execution-23A341-iphone17,2/kernel-filesets-stock"
                "/com.apple.driver.AppleMobileFileIntegrity")
        self.assertTrue((ROOT / amfi).exists())
        for cited in ("getReadOnlyData", "initReadOnlyData", "getOSEntitlements"):
            self.assertIn(cited, source)
        self.assertIn("the read-only-data pointer is the field at", source)
        self.assertIn("[x0, #0x78]", source)
        self.assertIn("0x8b90", source)
        # The fields *inside* the read-only object are derived from the same
        # image too, and each one is cited rather than asserted: the owner
        # write/check, the 0x48-byte CoreEntitlements context span, the
        # ro+0x08 self-pointer write and read, and the decoded-item struct
        # (`*out = ctx + 0x8`, then its +0x28/+0x30 begin/end).
        for cited_offset in ("zalloc_ro_mut(zone, ro, 0x0, &this, 8)",
                             "0xfffffff00976e138", "0xfffffff00976e048",
                             "0xfffffff00976e1cc", "0xfffffff00976e1e4",
                             "*out = ctx + 0x8"):
            self.assertIn(cited_offset, source)
        self.assertIn("+0x38  DER begin", source)
        self.assertIn("+0x40  DER end", source)

    def test_needle_and_citation_match_the_pinned_kext(self) -> None:
        data = KEXT.read_bytes()
        # The probe's needle is the entitlement the kext itself checks ...
        self.assertIn(ENTITLEMENT.encode(), data)
        source = SOURCE.read_text()
        self.assertIn(f'"{ENTITLEMENT}"', source)
        # ... and the "entitlement missing" log the probe quotes is real.
        self.assertIn(b"IOUE_UC:: %s entitlement missing", data)
        self.assertIn("IOUE_UC:: %s entitlement missing", source)

    def test_finished_probe_does_not_read_as_still_running(self) -> None:
        source = SOURCE.read_text()
        # "auditing" is only ever a live state: once RunOnce has returned the
        # report has to carry a terminal state, or a completed report reads as
        # an unfinished run.
        run_once = source.index(
            "CNDPhysicalEntitlementAuditRunOnce();")
        released = source.index(
            "__sync_lock_release(&gCNDPhysicalEntitlementAuditProbeRunning);")
        terminal = source.index('@"state", @"finished"')
        self.assertLess(run_once, released)
        self.assertLess(released, terminal)

        # The row's title, tint and enablement all come from IsRunning(), so
        # the section must be rebuilt when the probe finishes — and the
        # completion has to end the Activity sheet's footer, which only stops
        # on the installer's completion notification.
        settings = SETTINGS.read_text()
        self.assertIn("- (void)finishProbeActivityForRow:(NSInteger)row",
                      settings)
        self.assertIn("settings_post_actions_complete_async(", settings)
        self.assertIn('@"physical-krw-entitlement-audit-complete";', settings)
        self.assertRegex(
            settings,
            r"- \(void\)reloadProbeRows\s*\{[^}]*RootSectionProbes",
        )
        logged = settings.index(
            '"[ENTITLEMENT_AUDIT] result=%s donor=%s "')
        finished = settings.index(
            "[strongSelf finishProbeActivityForRow:row", logged)
        self.assertLess(logged, finished)


if __name__ == "__main__":
    unittest.main()
