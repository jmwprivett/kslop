#!/usr/bin/env python3
"""Static safety and provenance contract for the physical E1 observer."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class UATE1ObserveProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (ROOT / "Cyanide/probes/CNDUatE1ObserveProbe.m").read_text()
        cls.krw_source = (
            ROOT / "Cyanide/kexploit/kexploit_opa334.m"
        ).read_text()
        cls.krw_header = (
            ROOT / "Cyanide/kexploit/kexploit_opa334.h"
        ).read_text()
        cls.probe_skill = (
            ROOT / ".agents/skills/cyanide-probe-evidence/SKILL.md"
        ).read_text()

    def test_hop0_uses_exact_port_object_and_kernel_auth_dispatch(self) -> None:
        self.assertIn('"task_get_ipc_port_object"', self.source)
        self.assertIn('"off_ipc_port_ip_kobject"', self.source)
        self.assertIn("CNDUatE1IPKObjectOffset = 0x50", self.source)
        self.assertIn("IOConnectGetService(observer", self.source)
        self.assertIn("CNDUatE1ExpectedNoService", self.source)
        self.assertIn("0xe00002c7u", self.source)
        self.assertIn("clientRawAfter != clientRawBefore", self.source)
        self.assertNotIn("mach_port_kobject(", self.source)

    def test_client_class_vptr_gate_precedes_provider_field(self) -> None:
        self.assertIn(
            "CNDUatE1AGXDeviceUserClientVtable =\n"
            "    0xfffffff007cd3d78ull",
            self.source,
        )
        class_gate = self.source.index('@"hop1.client-class"')
        provider_read = self.source.index('@"read-client-provider"')
        self.assertLess(class_gate, provider_read)
        self.assertIn(
            '@"hop1-client-class-predicate-failed"', self.source
        )
        self.assertIn("0x8ab04e0..0x8ab0518", self.source)
        self.assertIn("0x7cd4028/0x7cd42e8/0x7cd4348", self.source)

    def test_iomachport_is_validated_before_unwrapping_client(self) -> None:
        self.assertIn(
            "CNDUatE1IOMachPortVtable =\n"
            "    0xfffffff007c79000ull", self.source
        )
        self.assertIn("CNDUatE1IOMachPortObject = 0x20", self.source)
        wrapper_gate = self.source.index('@"hop0.iomachport"')
        unwrap_read = self.source.index(
            '@"read-iomachport-object"', wrapper_gate
        )
        client_gate = self.source.index('@"hop1.client-class"')
        provider_read = self.source.index('@"read-client-provider"')
        self.assertLess(wrapper_gate, unwrap_read)
        self.assertLess(unwrap_read, client_gate)
        self.assertLess(client_gate, provider_read)
        self.assertIn("wrapper + CNDUatE1IOMachPortObject", self.source)
        self.assertIn('report[@"hop0WrapperShapePredicate"]', self.source)
        self.assertIn('@"hop0-iomachport-vptr-failed"', self.source)
        self.assertIn('0x836d320..0x836d360', self.source)

    def test_unwrapped_client_uses_eight_byte_shape_before_vptr(self) -> None:
        self.assertIn('report[@"hop0ClientShapePredicate"]', self.source)
        self.assertIn("bool clientAligned8 = (client & 0x7) == 0", self.source)
        self.assertIn('bool clientShapePassed = client != 0 && clientAligned8',
                      self.source)
        self.assertIn('"aligned16DiagnosticOnly"', self.source)
        self.assertNotIn("if (client == 0 || (client & 0xf) != 0)", self.source)
        shape_gate = self.source.index("if (!clientShapePassed)")
        class_gate = self.source.index('@"hop1.client-class"')
        provider_read = self.source.index('@"read-client-provider"')
        self.assertLess(shape_gate, class_gate)
        self.assertLess(class_gate, provider_read)

    def test_el0_pac_reauthentication_is_not_used_as_kernel_evidence(self) -> None:
        self.assertNotIn("CNDUatE1PACDA", self.source)
        self.assertNotIn("PACModifierTop", self.source)
        self.assertNotIn("rederivedVptr", self.source)
        self.assertIn("CNDUatE1ValidateLifecycleVptr", self.source)
        self.assertIn(
            '@"el0PACReauthenticationAttempted": @NO', self.source
        )
        self.assertIn(
            '@"kernel-authenticated-lifecycle-plus-exact-vtable"',
            self.source,
        )

    def test_every_object_type_names_its_artifact_auth_site(self) -> None:
        for witness in (
            "0xa4ff454..0xa4ff46c",
            "0x8a74408",
            "0x8b4e9e8/0x8b4eac0",
            "0x89f3a38",
        ):
            self.assertIn(witness, self.source)

    def test_kernel_memory_path_remains_read_only_and_bounded(self) -> None:
        self.assertIn('@"kernelWriteUsed": @NO', self.source)
        self.assertIn('@"kernelWriteCount": @0', self.source)
        self.assertIn('@"pointerScanUsed": @NO', self.source)
        self.assertIn('@"getPTEInvoked": @NO', self.source)
        self.assertIn('@"queueProbeInvoked": @NO', self.source)
        self.assertNotIn("api.write64(", self.source)
        self.assertNotIn("api->write64(", self.source)
        self.assertNotIn("IOConnectCallMethod", self.source)

    def test_shared_lifecycle_is_followed_by_exact_checked_read(self) -> None:
        self.assertIn('"kexploit_krw_read_checked"', self.source)
        self.assertIn("return api->checkedRead(address, buffer, length);", self.source)
        self.assertIn('@"existingKrwCheckedRead"] = @YES', self.source)
        self.assertIn(
            '@"krwPreparationOwner": '
            '@"settings_ensure_existing_krw_for_probe"',
            self.source,
        )
        self.assertIn(
            '@"krwPolicy": @"shared-tweak-lifecycle-existing-only"',
            self.source,
        )
        self.assertNotIn('krwAcquisitionAttempted', self.source)
        self.assertNotIn('krwRecoveryAttempted', self.source)
        self.assertNotIn('"kexploit_krw_ready"', self.source)
        self.assertNotIn('"krw_persistence_has_saved_recovery"', self.source)
        self.assertNotIn('krw_persistence_recover', self.source)
        self.assertNotIn("kexploit_opa334()", self.source)
        self.assertNotIn("|| !api.ready()", self.source)
        self.assertIn(
            "bool kexploit_krw_read_checked(uint64_t where, void *buffer, size_t size)",
            self.krw_header,
        )
        self.assertIn(
            "bool kexploit_krw_read_checked(uint64_t where, void *buffer, size_t size) {",
            self.krw_source,
        )
        self.assertIn("early_kread_checked(where + offset", self.krw_source)

    def test_probe_resolves_no_raw_read_or_write_primitive(self) -> None:
        self.assertNotIn('dlsym(RTLD_DEFAULT, "kreadbuf")', self.source)
        self.assertNotIn('dlsym(RTLD_DEFAULT, "kwrite64")', self.source)
        self.assertNotIn("CNDUatE1ReadFn", self.source)
        self.assertNotIn("CNDUatE1Write64Fn", self.source)
        self.assertIn(
            '@"probePrimitiveAPI": @"kexploit_krw_read_checked"',
            self.source,
        )
        self.assertIn('@"probeOwnsKRWLifecycle": @NO', self.source)
        self.assertIn("krw_park_rw_socket_locked()", self.krw_source)
        self.assertIn("krw_verify_rw_socket_parked_locked()", self.krw_source)

    def test_route1_ttbat_alias_is_guarded_before_first_table_read(self) -> None:
        self.assertIn(
            "CNDUatE1IOUATMapsReady = 0xfffffff00b2fe410ull",
            self.source,
        )
        self.assertIn(
            "CNDUatE1TTBATMapVA = 0xfffffff00b2fe428ull",
            self.source,
        )
        self.assertIn("CNDUatE1TTBATEntries = 64", self.source)
        self.assertIn("CNDUatE1TTBATStride = 16", self.source)
        self.assertIn("uint64_t words[CNDUatE1TTBATEntries * 2]", self.source)
        ready_gate = self.source.index("if (ready != 2)")
        map_slot_read = self.source.index(
            '@@"read-retained-map-va"'.replace("@", ""), ready_gate
        )
        table_read = self.source.index(
            '@@"before.ttbat"'.replace("@", ""), map_slot_read
        )
        self.assertLess(ready_gate, map_slot_read)
        self.assertLess(map_slot_read, table_read)
        self.assertIn("bool canonicalMatches = ttbatRaw == ttbat", self.source)
        self.assertIn("aligned16K", self.source)
        self.assertIn("activeRangeInOneMappedPage", self.source)
        self.assertIn(
            'C26-E1-TTBAT-EL1-MAP-LIFETIME-TRACE-20261105',
            self.source,
        )

    def test_route1_snapshots_one_named_action_and_decodes_roots(self) -> None:
        before = self.source.index('@@"before.ttbat"'.replace("@", ""))
        prepare = self.source.index(
            '@@"metal-prepare-one-blit"'.replace("@", ""), before
        )
        prepared = self.source.index(
            '@@"prepared.ttbat"'.replace("@", ""), prepare
        )
        submit = self.source.index(
            '@@"metal-submit-wait-verify"'.replace("@", ""), prepared
        )
        submitted = self.source.index(
            '@@"submitted.ttbat"'.replace("@", ""), submit
        )
        release = self.source.index(
            '@@"metal-release-objects"'.replace("@", ""), submitted
        )
        pool = self.source.rindex("@autoreleasepool {", before, prepare)
        pool_end = self.source.index(
            "\n    }\n    if (metalHandle != NULL)", release
        )
        after = self.source.index(
            '@@"after-release.ttbat"'.replace("@", ""), release
        )
        self.assertLess(pool, prepare)
        self.assertLess(before, prepare)
        self.assertLess(prepare, prepared)
        self.assertLess(prepared, submit)
        self.assertLess(submit, submitted)
        self.assertLess(submitted, release)
        self.assertLess(release, pool_end)
        self.assertLess(pool_end, after)
        self.assertLess(release, after)
        self.assertIn('@"schemaVersion": @11', self.source)
        self.assertIn('@@"setupChanges"'.replace("@", ""), self.source)
        self.assertIn('@@"submitChanges"'.replace("@", ""), self.source)
        self.assertIn('@@"releaseChanges"'.replace("@", ""), self.source)
        self.assertIn('@@"netChanges"'.replace("@", ""), self.source)
        self.assertIn('@@"clearedOnReleaseCount"'.replace("@", ""), self.source)
        self.assertIn('@@"ttbatSnapshotCount"'.replace("@", ""), self.source)
        self.assertIn("[metalCommand commit]", self.source)
        self.assertIn("[metalCommand waitUntilCompleted]", self.source)
        self.assertIn("metalFillVerified", self.source)
        self.assertIn("CNDUatE1TTBATPaddrMask", self.source)
        self.assertIn("CNDUatE1TTBATContextMask", self.source)
        self.assertIn('@@"contextID"'.replace("@", ""), self.source)
        self.assertIn('@@"paddr"'.replace("@", ""), self.source)
        self.assertIn('@@"clearedOnClose"'.replace("@", ""), self.source)
        self.assertIn('@@"changedEntryCount"'.replace("@", ""), self.source)

    def test_route1_reads_context_ids_only_after_exact_gart_gate(self) -> None:
        context_read = self.source.index(
            '@@"read-phase-gart-context-id"'.replace("@", "")
        )
        phase_gart_gate = self.source.rindex(
            "CNDUatE1GartVtable, slide", 0, context_read
        )
        anchor_store = self.source.index(
            "route1Garts[validatedRoute1GartCount].address"
        )
        main_gart_gate = self.source.rindex(
            "CNDUatE1GartVtable, slide", 0, anchor_store
        )
        self.assertLess(phase_gart_gate, context_read)
        self.assertLess(main_gart_gate, anchor_store)
        self.assertIn("CNDUatE1GartContextID0 = 0x230", self.source)
        self.assertIn("CNDUatE1GartContextIDCount = 4", self.source)
        self.assertIn("contextID == UINT32_MAX", self.source)
        self.assertIn("contextID < CNDUatE1TTBATEntries", self.source)
        self.assertIn("CNDUatE1Read32(api, contextField", self.source)
        self.assertIn("0x8a88c48", self.source)
        self.assertIn("+0x230/+0x234/+0x238/+0x23c", self.source)
        self.assertIn(
            '@"TA", @"3D", @"CL", @"accelerator-bootstrap"',
            self.source,
        )
        self.assertIn("0x8b3d43c", self.source)
        self.assertIn("0x8a6f284", self.source)
        self.assertIn("0x8a98a48", self.source)
        self.assertIn("0x8a7f908", self.source)
        self.assertIn("CNDUatE1AssociateGartContextsWithTTBAT", self.source)
        self.assertIn('@"route1ContextRootAssociations"', self.source)
        self.assertIn('@"beforeGartContextSnapshot"', self.source)
        self.assertIn('@"preparedGartContextSnapshot"', self.source)
        self.assertIn('@"submittedGartContextSnapshot"', self.source)
        self.assertIn('@"afterReleaseGartContextSnapshot"', self.source)
        self.assertIn('@"route1ContextRootAssociationsByPhase"', self.source)

    def test_agx_bootstrap_root_route_stops_before_root_page_read(self) -> None:
        for pin in (
            "CNDUatAGXAcceleratorBootstrapGart = 0xd0",
            "CNDUatE1GartVtable = 0xfffffff007cd9148ull",
            "CNDUatE1GartContextID0 = 0x230",
            "CNDUatE1IOUATMapsReady",
            "CNDUatE1TTBATMapVA",
            '"0xfffffc0000056f08"',
            '@"com.zeroxjf.cyanide.uat-agx-bootstrap-root"',
        ):
            self.assertIn(pin, self.source)
        route = self.source.index(
            "static bool CNDUatAGXRunBootstrapRootRoute"
        )
        route_end = self.source.index(
            "static bool CNDUatE2TranslateContiguousPages", route
        )
        body = self.source[route:route_end]
        gart = body.index("accelerator + CNDUatAGXAcceleratorBootstrapGart")
        gart_gate = body.index("CNDUatE1GartVtable", gart)
        context = body.index("3 * sizeof(uint32_t)", gart_gate)
        ready = body.index("CNDUatE1IOUATMapsReady", context)
        ttbat_map = body.index("CNDUatE1TTBATMapVA", ready)
        first_snapshot = body.index("CNDUatE1SnapshotTTBAT", ttbat_map)
        root_words = body.index("first.words[0]", first_snapshot)
        stability = body.index(
            '@"agxBootstrapAssociationStabilityPredicate"', root_words
        )
        gate_reached = body.index(
            '@"agxBootstrapRootAssociationGateReached"] = @YES', stability
        )
        self.assertLess(gart, gart_gate)
        self.assertLess(gart_gate, context)
        self.assertLess(context, ready)
        self.assertLess(ready, ttbat_map)
        self.assertLess(ttbat_map, first_snapshot)
        self.assertLess(first_snapshot, root_words)
        self.assertLess(root_words, stability)
        self.assertLess(stability, gate_reached)
        self.assertIn("CNDUatE2ReadStable64", body)
        self.assertIn('@"rootPagesRead": @NO', body)
        self.assertIn('@"rootMappednessClaimed": @NO', body)
        self.assertIn('@"walkAuthorized": @NO', body)
        self.assertIn('@"kernelWriteUsed"] = @NO', body)
        self.assertIn('@"kernelWriteCount"] = @0', body)
        self.assertNotIn("CNDUatE3ResolveLivePath", body)
        self.assertNotIn("kwrite", body)
        self.assertNotIn("IOConnectCall", body)
        self.assertIn("CNDUatAGXRunBootstrapRootRoute(", self.source)
        self.assertIn("void CNDUatAGXBootstrapRootRun(", self.source)
        self.assertIn(
            "NO, NO, NO, NO, NO, NO, NO, YES, NO, completion",
            self.source,
        )

    def test_agx_rtbuddy_alias_route_names_and_gates_panic_risk(self) -> None:
        for pin in (
            "CNDUatAGXArmFirmwareASCVtable =",
            "0xfffffff007cd5360ull",
            "0xfffffff008174848ull",
            "0xfffffff008176938ull",
            "0xfffffff008170e08ull",
            "0xfffffff007c66da0ull",
            "0xfffffff008172ce8ull",
            "0xfffffff007c70d10ull",
            'com.zeroxjf.cyanide.uat-agx-rtbuddy-alias',
            "CNDUatAGXRunRTBuddyAliasRoute",
            "CNDUatAGXRTBuddyAliasRun",
        ):
            self.assertIn(pin, self.source)
        route = self.source.index("static bool CNDUatAGXRunRTBuddyAliasRoute")
        route_end = self.source.index(
            "static bool CNDUatE2TranslateContiguousPages", route
        )
        body = self.source[route:route_end]
        firmware = body.index("CNDUatAGXAcceleratorFirmwareASC")
        channel = body.index("CNDUatAGXFirmwareChannel0", firmware)
        rtbuddy = body.index("CNDUatAGXChannelRTBuddy", channel)
        loaded = body.index("CNDUatAGXRTBuddyFirmware", rtbuddy)
        coredump = body.index("CNDUatAGXRTBuddyCoredumpMap", loaded)
        arrays = body.index("CNDUatAGXCoredumpSegments", coredump)
        metadata = body.index("CNDUatAGXReadOSArrayMetadata", arrays)
        risk = body.index("explicit-panic-risk-bounded-backing-read", metadata)
        segment_gate = body.index("CNDUatAGXRTBuddySegmentVtable", risk)
        paired_risk = body.index(
            "explicit-panic-risk-one-paired-element-read", segment_gate
        )
        map_gate = body.index("CNDUatAGXIOMemoryMapVtable", paired_risk)
        output = body.index("read-command20-index0-output-word", map_gate)
        passed = body.index('@"agxRTBuddyAliasGateReached"] = @YES', output)
        self.assertLess(firmware, channel)
        self.assertLess(channel, rtbuddy)
        self.assertLess(rtbuddy, loaded)
        self.assertLess(loaded, coredump)
        self.assertLess(coredump, arrays)
        self.assertLess(arrays, metadata)
        self.assertLess(metadata, risk)
        self.assertLess(risk, segment_gate)
        self.assertLess(segment_gate, paired_risk)
        self.assertLess(paired_risk, map_gate)
        self.assertLess(map_gate, output)
        self.assertLess(output, passed)
        self.assertIn('@"kernelPACValidated": @NO', self.source)
        self.assertIn('@"explicitPanicRiskAccepted": @YES', self.source)
        self.assertIn("CNDUatAGXRTBuddyMaximumSegments = 8", self.source)
        self.assertIn("segmentMetadata.count != cpuMapMetadata.count", body)
        self.assertIn('report[@"kernelWriteUsed"] = @NO', body)
        self.assertIn('report[@"kernelWriteCount"] = @0', body)
        self.assertNotIn("IOConnectCall", body)
        self.assertNotIn("GET_PT_ENTRY", body)
        self.assertNotIn("CNDUatE3ResolveLivePath", body)
        self.assertIn(
            "NO, NO, NO, NO, NO, NO, NO, NO, YES, completion",
            self.source,
        )

    def test_route1_reaches_per_task_gart_through_validated_client(self) -> None:
        self.assertIn(
            "CNDUatE1AGXSharedVtable = 0xfffffff007cdefb8ull",
            self.source,
        )
        self.assertIn("CNDUatE1ClientTask = 0x120", self.source)
        self.assertIn("CNDUatE1TaskGart = 0x58", self.source)
        client_gate = self.source.index('@"hop1.client-class"')
        task_read = self.source.index('@"read-client-task"', client_gate)
        task_gate = self.source.index('@"hop1.task-class"', task_read)
        gart_read = self.source.index('@"read-task-gart"', task_gate)
        gart_gate = self.source.index('@"hop2.task-gart-class"', gart_read)
        anchor_store = self.source.index(
            "route1Garts[validatedRoute1GartCount].address = taskGart",
            gart_gate,
        )
        self.assertLess(client_gate, task_read)
        self.assertLess(task_read, task_gate)
        self.assertLess(task_gate, gart_read)
        self.assertLess(gart_read, gart_gate)
        self.assertLess(gart_gate, anchor_store)
        self.assertIn("client + CNDUatE1ClientTask", self.source)
        self.assertIn("task + CNDUatE1TaskGart", self.source)
        self.assertIn("0xa5026cc..0xa502708", self.source)
        self.assertIn("0xa52c0b4..0xa52c0e4", self.source)
        self.assertIn("0xa51cf4c..0xa51cf88", self.source)
        self.assertIn("0x8b2e4dc..0x8b2e508", self.source)
        self.assertIn('@"perTaskGartReached"] = @YES', self.source)
        self.assertIn('@"anchorKind": anchorKind', self.source)
        self.assertIn('@"observer-client-task"', self.source)

    def test_per_task_gart_is_the_command_descriptor_consumer(self) -> None:
        self.assertIn("0xa52e294..0xa52e2ac", self.source)
        self.assertIn("task+0x58 to queue+0x488", self.source)
        self.assertIn("0xa530bdc..0xa5254dc", self.source)
        self.assertIn("descriptor+0x58", self.source)
        self.assertIn("CNDUatE1ValidatedGart route1Garts[6]", self.source)
        self.assertIn(".perTask = true", self.source)
        self.assertIn(".perTask = false", self.source)

    def test_per_task_resolver_domains_are_exact_and_individually_gated(self) -> None:
        for constant in (
            "CNDUatE1GartResolverDomain1 = 0x338",
            "CNDUatE1GartResolverDomain3 = 0x340",
            "CNDUatE1GartResolverDomain7 = 0x348",
        ):
            self.assertIn(constant, self.source)
        self.assertIn(
            "const NSUInteger resolverDomainSelectors[3] = {1, 3, 7}",
            self.source,
        )
        parent_gate = self.source.index('@"hop2.task-gart-class"')
        domain_read = self.source.index('@"read-resolver-domain-gart"')
        domain_gate = self.source.index(
            "CNDUatE1GartVtable, slide,",
            domain_read,
        )
        domain_store = self.source.index(
            ".address = domainGart",
            domain_gate,
        )
        self.assertLess(parent_gate, domain_read)
        self.assertLess(domain_read, domain_gate)
        self.assertLess(domain_gate, domain_store)
        self.assertIn('domainReport[@"result"] = @"null-skipped"', self.source)
        self.assertIn("0x8af7118", self.source)
        self.assertIn("0x8b12b04", self.source)
        self.assertIn("0x8b2db20..0x8b2dc6c", self.source)
        self.assertIn("0x8a7bf58", self.source)
        self.assertIn(".resolverSelector = selector", self.source)
        self.assertIn(".derivedDomain = true", self.source)
        self.assertIn('@"observer-client-task-resolver-domain"', self.source)

    def test_metal_device_connection_bridge_is_exact_and_userland_only(self) -> None:
        self.assertIn("#import <objc/runtime.h>", self.source)
        self.assertIn(
            "CNDUatE1MetalDeviceRefOffset = 0x278", self.source
        )
        self.assertIn(
            "CNDUatE1MetalAcceleratorPortOffset = 0x280", self.source
        )
        self.assertIn(
            "CNDUatE1DeviceRefConnectionOffset = 0x14", self.source
        )
        self.assertIn(
            'NSClassFromString(@"IOGPUMetalDevice")', self.source
        )
        self.assertIn(
            'class_getInstanceVariable(concreteMetalClass, "_deviceRef")',
            self.source,
        )
        self.assertIn(
            'class_getInstanceVariable(concreteMetalClass, '
            '"_acceleratorPort")',
            self.source,
        )
        self.assertIn("ivar_getOffset(deviceRefIvar)", self.source)
        self.assertIn("ivar_getTypeEncoding(deviceRefIvar)", self.source)
        self.assertIn(
            'strcmp(deviceRefType, "^{__IOGPUDevice=}") == 0', self.source
        )
        self.assertIn("ivar_getOffset(acceleratorPortIvar)", self.source)
        self.assertIn("ivar_getTypeEncoding(acceleratorPortIvar)", self.source)
        self.assertIn('strcmp(acceleratorPortType, "I") == 0', self.source)
        class_gate = self.source.index("bool metalClassPassed")
        ref_gate = self.source.index("bool metalDeviceRefIvarPassed", class_gate)
        service_gate = self.source.index("bool metalServiceIvarPassed", ref_gate)
        ref_copy = self.source.index("memcpy(&metalDeviceRef", service_gate)
        connection_copy = self.source.index("memcpy(&metalConnection", ref_copy)
        right_gate = self.source.index("mach_port_type(", connection_copy)
        self.assertLess(class_gate, ref_gate)
        self.assertLess(ref_gate, service_gate)
        self.assertLess(service_gate, ref_copy)
        self.assertLess(ref_copy, connection_copy)
        self.assertLess(connection_copy, right_gate)
        self.assertIn('report[@"metalDeviceConnectionBridge"]', self.source)
        self.assertIn("deviceRefService == metalService", self.source)
        self.assertNotIn("object_getIvar", self.source)
        self.assertNotIn("IOServiceClose(metalConnection)", self.source)

    def test_metal_port_reuses_the_exact_bounded_connection_chain(self) -> None:
        helper = self.source.index("static bool CNDUatE1ResolveConnectionGarts")
        helper_end = self.source.index(
            "static NSDictionary<NSString *, id> *CNDUatE1TTBATDecodedWord",
            helper,
        )
        body = self.source[helper:helper_end]
        port = body.index("api->portObject(selfTask, connection)")
        auth = body.index("IOConnectGetService(connection", port)
        wrapper_gate = body.index("CNDUatE1IOMachPortVtable", auth)
        unwrap = body.index("wrapper + CNDUatE1IOMachPortObject", wrapper_gate)
        client_gate = body.index("CNDUatE1AGXDeviceUserClientVtable", unwrap)
        task_read = body.index("client + CNDUatE1ClientTask", client_gate)
        task_gate = body.index("CNDUatE1AGXSharedVtable", task_read)
        gart_read = body.index("task + CNDUatE1TaskGart", task_gate)
        gart_gate = body.index("CNDUatE1GartVtable", gart_read)
        domain_read = body.index("read-task-resolver-domain", gart_gate)
        domain_gate = body.index("CNDUatE1GartVtable", domain_read)
        self.assertLess(port, auth)
        self.assertLess(auth, wrapper_gate)
        self.assertLess(wrapper_gate, unwrap)
        self.assertLess(unwrap, client_gate)
        self.assertLess(client_gate, task_read)
        self.assertLess(task_read, task_gate)
        self.assertLess(task_gate, gart_read)
        self.assertLess(gart_read, gart_gate)
        self.assertLess(gart_gate, domain_read)
        self.assertLess(domain_read, domain_gate)
        self.assertIn("metalAction = true", body)
        self.assertIn('@"null-skipped"', body)

    def test_metal_task_garts_are_phase_local_and_not_read_after_release(self) -> None:
        self.assertIn(
            "CNDUatE1ValidatedGart preparedPhaseGarts["
            "CNDUatE1MaxPhaseGarts]",
            self.source,
        )
        self.assertIn(
            "CNDUatE1ValidatedGart submittedPhaseGarts["
            "CNDUatE1MaxPhaseGarts]",
            self.source,
        )
        self.assertIn('metalConnection, @"prepared"', self.source)
        self.assertIn('metalConnection, @"submitted"', self.source)
        self.assertIn(
            '@"preparedGartContextSnapshot", preparedPhaseGarts',
            self.source,
        )
        self.assertIn(
            '@"submittedGartContextSnapshot", submittedPhaseGarts',
            self.source,
        )
        release = self.source.index('@"metal-release-objects"')
        after = self.source.index('@"after-release.ttbat"', release)
        after_context = self.source.index(
            '@"afterReleaseGartContextSnapshot"', after
        )
        after_slice = self.source[after:after_context + 200]
        self.assertIn("garts, gartCount", after_slice)
        self.assertNotIn("preparedPhaseGarts", after_slice)
        self.assertNotIn("submittedPhaseGarts", after_slice)
        self.assertIn('@"metal-device-task"', self.source)
        self.assertIn('@"metal-device-task-resolver-domain"', self.source)

    def test_probe_skill_requires_the_shared_tweak_lifecycle(self) -> None:
        self.assertIn(
            "Use the shared KRW lifecycle; do not fork it inside a probe",
            self.probe_skill,
        )
        self.assertIn(
            "calls `settings_ensure_krw_for_probe()`",
            self.probe_skill,
        )
        self.assertIn(
            "`settings_ensure_existing_krw_for_probe()`",
            self.probe_skill,
        )
        self.assertIn(
            "never fall through to `kexploit_opa334()`",
            self.probe_skill,
        )
        self.assertIn(
            "must not introduce a probe-specific parked",
            self.probe_skill,
        )
        self.assertIn(
            "Do not claim that recovery or\n  acquisition was skipped",
            self.probe_skill,
        )

    def test_report_is_incremental_and_uses_full_t1sz_pointer_width(self) -> None:
        self.assertIn('CNDUatE1Observe.json', self.source)
        self.assertIn("CNDUatE1Persist(report);", self.source)
        self.assertLess(
            self.source.index("api->offsetsInit();"),
            self.source.index("uint64_t t1sz = *api->t1sz;"),
        )
        self.assertIn("unsigned bits = (unsigned)(64 - t1sz);", self.source)
        self.assertIn("api->pointerMask = (UINT64_C(1) << bits) - 1", self.source)

    def test_self_task_uses_physically_observed_eight_byte_alignment(self) -> None:
        self.assertIn('report[@"hop0SelfTaskPredicate"]', self.source)
        self.assertIn("bool selfTaskAligned8 = (selfTask & 0x7) == 0", self.source)
        self.assertIn('@"requiredAlignment": @8', self.source)
        self.assertIn('@"0xffffffdd38544a68"', self.source)
        self.assertIn('@"0xffffffdd372b3408"', self.source)
        self.assertIn('@"aligned16DiagnosticOnly"', self.source)
        self.assertNotIn("(selfTask & 0xf) != 0", self.source)

    def test_ipc_port_object_uses_existing_kernel_object_alignment_contract(self) -> None:
        self.assertIn('report[@"hop0PortObjectPredicate"]', self.source)
        self.assertIn("(portObjectBefore & 0x7) == 0", self.source)
        self.assertNotIn("(portObjectBefore & 0xf) != 0", self.source)


if __name__ == "__main__":
    unittest.main()
