#!/usr/bin/env python3
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Cyanide" / "probes" / "CNDHailMaryPageWire.m"
HEADER = ROOT / "Cyanide" / "probes" / "CNDHailMaryPageWire.h"
PATCH = ROOT / "Cyanide" / "probes" / "CNDHailMaryPatch.m"
PATCH_HEADER = ROOT / "Cyanide" / "probes" / "CNDHailMaryPatch.h"
PROBE = ROOT / "Cyanide" / "probes" / "CNDHailMaryProbe.m"
PROBE_HEADER = ROOT / "Cyanide" / "probes" / "CNDHailMaryProbe.h"
APP_DELEGATE = ROOT / "Cyanide" / "AppDelegate.m"
SETTINGS = ROOT / "Cyanide" / "SettingsViewController.m"
SETTINGS_HEADER = ROOT / "Cyanide" / "SettingsViewController.h"


class HailMaryPageWireTests(unittest.TestCase):
    def test_probe_is_read_only_and_never_writes_kernel_memory(self):
        source = SOURCE.read_text()
        self.assertIn('@"hail-mary-read-only-data-page-wire-probe"', source)
        self.assertIn('@"springboard-mlock-no-mutation"', source)
        self.assertIn('@"kernelWritePrimitiveInvocationCount": @0', source)
        self.assertIn('@"semanticMutationCount": @0', source)
        self.assertIn('@"targetProcessDirectMutationCount": @0', source)
        for banned in (
            "kwrite32(",
            "kwrite64(",
            "kwritebuf(",
            "kwrite_zone_element",
            "mach_vm_write",
            "r_dlsym_call",
        ):
            self.assertNotIn(banned, source, banned)

    def test_exact_ro_data_page_identity_is_pinned(self):
        source = SOURCE.read_text().lower()
        for token in (
            "ceeb0d68-9ba9-3cc8-aeb1-8f23bac92b58",
            "dyld_shared_cache_arm64e.34.dyldreadonly",
            "0x1ffc27458",
            "0x3458",
            "0x4000",
            "iphone17,2",
            "23a341",
        ):
            self.assertIn(token, source, token)
        compact = source.replace(" ", "")
        self.assertIn('"mappinginitprotection":@1', compact)
        self.assertIn('"mappingmaximumprotection":@1', compact)

    def test_page_identity_is_delegated_to_the_proven_resolver(self):
        source = SOURCE.read_text()
        self.assertIn(
            "CNDHailMaryReadOnlyDataPageResolveDispatchEntry", source
        )
        # Both page states are acceptable: the wire targets the frame, not the
        # dispatch value. The resolver is asked for the original guard first.
        original = source.index(
            "CNDHailMaryReadOnlyDataPageResolveDispatchEntryWithMode(\n"
            "                    CNDHailMaryProofModeSpringBoardOnly, probeReport, NO"
        )
        redirected = source.index(
            "CNDHailMaryReadOnlyDataPageResolveDispatchEntryWithMode(\n"
            "                        CNDHailMaryProofModeSpringBoardOnly, probeReport, YES"
        )
        self.assertLess(original, redirected)
        self.assertIn('pageState = @"original";', source)
        self.assertIn('pageState = @"redirected";', source)

    def test_pinned_identity_invariants_guard_the_wire_range(self):
        source = SOURCE.read_text()
        for token in (
            "physicalAddress - frame == offsetWithinFrame",
            "offsetWithinFrame ==\n"
            "                    kCNDHailMaryPageWireEntryOffsetWithinFrame",
            "frame != guardedTextPhysicalFrame",
            "frameKVA + offsetWithinFrame == windowKVA",
            "pageBase + offsetWithinFrame == runtimeAddress",
            "runtimeAddress - sharedCacheSlide ==\n"
            "                    kCNDHailMaryPageWireEntryUnslid",
            "(frameKVA & (kCNDHailMaryPageWirePageSize - 1)) == 0",
        ):
            self.assertIn(token, source, token)

    def test_durable_journal_precedes_the_single_wire_beat(self):
        source = SOURCE.read_text()
        self.assertIn('@"armed-springboard-page-wire"', source)
        armed = source.index('@"armed-springboard-page-wire"')
        returned_false = source.index('@"returned": @NO', armed)
        durable = source.index("CNDHailMaryPageWireSaveDurably", armed)
        wire = source.index("CNDHailMaryPatchWireSpringBoardPage(", durable)
        returned_true = source.index('@"returned": @YES', wire)
        self.assertLess(armed, returned_false)
        self.assertLess(returned_false, durable)
        self.assertLess(durable, wire)
        self.assertLess(wire, returned_true)
        self.assertEqual(
            source.count("CNDHailMaryPatchWireSpringBoardPage("), 1
        )
        self.assertIn('@"diagnosticControls": @YES', source)

    def test_guard_and_translation_are_reproved_after_the_wire(self):
        source = SOURCE.read_text()
        wire = source.index("CNDHailMaryPatchWireSpringBoardPage(")
        self.assertLess(wire, source.index('@"post-wire-identity-check"'))
        self.assertIn("kreadbuf(windowKVA, afterBytes", source)
        self.assertIn("[afterData isEqualToData:beforeData]", source)
        # SpringBoard is re-proved on its own: wiring may give it a private
        # leaf entry, which makes the shared-pair translator refuse even
        # though both processes still resolve the same physical frame.
        self.assertIn(
            "CNDHailMaryProbeTranslateRuntimeAddressInProcess(\n"
            '                        probeReport, @"SpringBoard"',
            source,
        )
        self.assertIn(
            "postFrame == frame &&\n"
            "                    postPhysical == physicalAddress",
            source,
        )
        self.assertIn('@"translationMode": @"springboard-only"', source)
        self.assertNotIn("sharedPairStillAgrees", source)
        self.assertNotIn('@"spotlightPID"', source)
        self.assertNotIn("spotlightLeafEntryAddress", source)
        self.assertIn(
            "BOOL confirmed = wireLanded && sessionClean && postStable;",
            source,
        )
        # A private copy is judged on the wired frame's guard, not on the
        # address staying pinned.
        self.assertIn("BOOL privateCopy = NO;", source)
        self.assertIn(
            "BOOL postStable = postWiredGuardStable &&\n"
            "                (postTranslationStable || privateCopy);",
            source,
        )
        self.assertIn('@"wiredFrameGuardStable"', source)
        self.assertIn('@"wiredFrameWindowKernelVirtualAddress"', source)
        self.assertIn(
            '"springboard-wire-accepted-private-copy"', source
        )
        self.assertIn('@"read-only-data-page-wire-confirmed"', source)
        self.assertIn('@"read-only-data-page-wire-refused"', source)

    def test_wire_accepts_only_the_private_leaf_entry_delta(self):
        patch = PATCH.read_text()
        header = PROBE_HEADER.read_text()
        self.assertIn(
            "CNDHailMaryPatchTranslationPathMatchesAfterWire", patch
        )
        self.assertIn(
            "kCNDHailMaryPatchPrivateLeafEntryBit = 0x800", patch
        )
        self.assertIn("kCNDHailMaryPatchLeafAddressMask", patch)
        self.assertIn('@"privateLeafEntry": @(privateLeafEntry)', patch)
        self.assertIn(
            "BOOL ok = identityBound && remoteOK && mlockResult == 0 && "
            "closed &&\n        !teardownDeferred && finalIdentity && "
            "translationPathStable;",
            patch,
        )
        self.assertIn(
            "CNDHailMaryProbeTranslateRuntimeAddressInProcess(", header
        )

    def test_retained_wire_records_its_inverse_and_follow_up(self):
        source = SOURCE.read_text()
        self.assertIn('@"releasedAutomaticallyOnSpringBoardExit": @YES', source)
        self.assertIn('@"longitudinalGuardCheckRequired": @YES', source)
        self.assertIn(
            'report[@"springBoardWireRetained"] = @(postStable);',
            source,
        )
        self.assertIn('@"frameMoved"', source)
        self.assertIn('@"privateCopy"', source)
        self.assertIn(
            "uint64_t candidate = frameKVA - frame + postPhysical;", source
        )
        self.assertIn('@"pageContentInverseRequired": @NO', source)

    def test_patch_module_exposes_one_wire_implementation(self):
        patch = PATCH.read_text()
        header = PATCH_HEADER.read_text()
        self.assertIn(
            "NSDictionary<NSString *, id> *CNDHailMaryPatchWireSpringBoardPage(",
            header,
        )
        self.assertIn('@"diagnosticControls"', header)
        self.assertNotIn(
            "static NSDictionary<NSString *, id> *\n"
            "CNDHailMaryPatchWireSpringBoardPage(",
            patch,
        )
        for token in (
            'CNDHailMaryPatchAnonymousMlockControl',
            '"mmap"',
            '"munmap"',
            '"mlock"',
            '@"anonymousReadWrite"',
            '@"anonymousReadOnly"',
            "kCNDHailMaryPatchProtectionReadWrite",
            "kCNDHailMaryPatchProtectionRead",
        ):
            self.assertIn(token, patch, token)
        self.assertIn(
            "CNDHailMaryPatchWireSpringBoardPage(context, nil)", patch
        )
        self.assertIn('report[@"mlockLanded"]', patch)

    def test_launch_argument_and_action_are_wired(self):
        app_delegate = APP_DELEGATE.read_text()
        settings = SETTINGS.read_text()
        header = SETTINGS_HEADER.read_text()
        self.assertIn('@"--hail-mary-page-wire"', app_delegate)
        self.assertIn(
            "settings_run_hail_mary_page_wire_action()", app_delegate
        )
        self.assertIn(
            "void settings_run_hail_mary_page_wire_action(void);", header
        )
        self.assertIn(
            "void settings_run_hail_mary_page_wire_action(void)\n{", settings
        )
        self.assertIn('#import "probes/CNDHailMaryPageWire.h"', settings)
        self.assertIn("CNDHailMaryPageWireRun(", settings)
        # The diagnostics stay hidden: the root action row count is pinned.
        self.assertIn("case RootSectionActions:        return 6;", settings)

    def test_probes_section_exposes_a_wire_button(self):
        settings = SETTINGS.read_text()
        # Fourth row of the dedicated Probes section; Quick Actions keeps its
        # pinned six rows, so no retained diagnostic is exposed by this.
        self.assertRegex(settings, r"case RootSectionProbes:\s+return 17;")
        self.assertIn("case RootSectionActions:        return 6;", settings)
        self.assertIn('@"Run Hail Mary .34 Page Wire"', settings)
        self.assertIn('@"Hail Mary .34 Wire Running…"', settings)
        self.assertIn('@"Run Hail Mary .34 Page Wire?"', settings)
        self.assertIn("CNDHailMaryPageWireIsSupported(&reason)", settings)
        self.assertIn("CNDHailMaryPageWireIsRunning()", settings)
        self.assertIn(
            'successResult = @"read-only-data-page-wire-confirmed";', settings
        )
        # The row reuses the shared body through the hook so exactly one
        # completion is posted and the row stops saying "Running…".
        self.assertIn(
            "static void settings_run_hail_mary_page_wire_with_hook(", settings
        )
        self.assertIn(
            "settings_run_hail_mary_page_wire_with_hook(nil);", settings
        )
        hook_call = settings.index(
            "settings_run_hail_mary_page_wire_with_hook(\n"
            "                    ^(NSDictionary<NSString *, id> *report) {"
        )
        self.assertLess(
            hook_call, settings.index("finishProbeActivityForRow:row",
                                      hook_call)
        )
        self.assertIn(
            "if (hook) {\n                    hook(report);\n"
            "                    return;",
            settings,
        )
        # Every pre-probe refusal resolves the row instead of leaving it up.
        self.assertIn(
            "static void settings_finish_hail_mary_page_wire_failure(", settings
        )
        for refusal in (
            '@"refused-actions-lock"',
            '@"refused-krw-unavailable"',
        ):
            self.assertIn(refusal, settings, refusal)
        wire_action = settings.split(
            "static void settings_run_hail_mary_page_wire_with_hook(", 1
        )[1].split(
            "void settings_run_hail_mary_page_wire_action(void)", 1
        )[0]
        self.assertNotIn("Spotlight", wire_action)
        self.assertNotIn("refused-spotlight-unavailable", settings)


if __name__ == "__main__":
    unittest.main()
