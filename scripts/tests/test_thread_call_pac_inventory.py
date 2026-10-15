"""Offline tests for the exact thread_call PAC-reuse inventory."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))

import cnd_thread_call_pac_inventory as inventory  # noqa: E402


class ThreadCallPACInventoryTests(unittest.TestCase):
    def test_app_boundary_uses_rea_bound_allproc_without_kcall(self) -> None:
        source = (
            ROOT / "Cyanide/CNDLabThreadCallPACBoundary.m"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "CNDStaticAllProc = UINT64_C(0xfffffe0009813020)", source,
        )
        self.assertIn(
            "ev_060e9c17a5b2806c1f7f39c92369c8755bd015728e56dd954f76eab1eb54bfdc",
            source,
        )
        self.assertIn("cnd_lab_krw_read(", source)
        self.assertIn("CNDLabThreadCallFindProcess(allprocHead", source)
        self.assertIn("CNDMaximumProcWalk = 1024", source)
        self.assertIn("CNDLabThreadCallStripDataPAC(rawNext)", source)
        self.assertNotIn("kutils_recover_self_proc_from", source)
        self.assertNotIn("task_get_ipc_port_object", source)
        self.assertNotIn("cnd_lab_kernel_call(", source)

    def test_vm_mutation_and_original_dispatch_are_bounded(self) -> None:
        source = (
            ROOT / "Cyanide/CNDLabThreadCallPACBoundary.m"
        ).read_text(encoding="utf-8")
        header = (
            ROOT / "Cyanide/CNDLabThreadCallPACBoundary.h"
        ).read_text(encoding="utf-8")
        settings = (
            ROOT / "Cyanide/SettingsViewController.m"
        ).read_text(encoding="utf-8")

        self.assertIn("CNDThreadCallParam1MutationCanary", source)
        self.assertIn("mutationAddress = timerObject + CNDMkTimerParam1Offset", source)
        self.assertGreaterEqual(source.count("cnd_lab_krw_write("), 3)
        self.assertIn('report[@"mutationReadbackVerified"]', source)
        self.assertIn('report[@"restoreReadbackVerified"]', source)
        self.assertIn('report[@"emergencyRestoreVerified"]', source)
        self.assertIn('@"armedTimer": @NO', source)
        self.assertIn('@"callbackDispatched": @NO', source)
        self.assertIn("CNDLabThreadCallPACBoundaryModeReversibleMutation", source)
        self.assertIn("CNDLabThreadCallPACBoundaryModeOriginalCallbackDispatch", source)
        self.assertIn("mk_timer_arm(timerPort, armDeadline)", source)
        self.assertIn("mk_timer_cancel(", source)
        self.assertIn('report[@"callbackIdentityStable"]', source)
        self.assertIn('report[@"exactQueuedState"]', source)
        self.assertIn('report[@"queuedMutationReadbackVerified"]', source)
        self.assertIn('report[@"armNormalizedParam1"]', source)
        self.assertIn('report[@"expirationMessageReceived"]', source)
        self.assertIn("MACH_RCV_MSG | MACH_RCV_TIMEOUT", source)
        self.assertIn('report[@"param1CanaryStableThroughDispatch"]', source)
        self.assertIn('report[@"timerQuiescedBeforeDestroy"]', source)
        self.assertIn('report[@"exactOriginalCallbackDispatch"]', source)
        self.assertNotIn("cnd_lab_kernel_call(", source)
        self.assertIn(
            "CNDLabThreadCallPACBoundaryRunReversibleMutation", header,
        )
        self.assertIn(
            "CNDLabThreadCallPACBoundaryRunOriginalCallbackDispatch", header,
        )
        self.assertIn("CNDLabThreadCallPACBoundaryRunPACReuseDispatch", header)
        self.assertIn("Run VM thread_call PAC Reuse", settings)
        self.assertIn(
            "Signed adapter + signed target • controlled x0", settings,
        )

    def test_vm_pac_reuse_dispatch_is_exact_and_fail_closed(self) -> None:
        source = (
            ROOT / "Cyanide/CNDLabThreadCallPACBoundary.m"
        ).read_text(encoding="utf-8")
        settings = (
            ROOT / "Cyanide/SettingsViewController.m"
        ).read_text(encoding="utf-8")

        for witness in (
            "CNDStaticBRAAZAdapter =",
            "UINT64_C(0xfffffe00080a0710)",
            "CNDStaticBRAAZAdapterObjectGlobal =",
            "UINT64_C(0xfffffe0009846d20)",
            "CNDStaticIAZeroTarget =",
            "UINT64_C(0xfffffe0007e3613c)",
            "CNDStaticIAZeroObjectGlobal =",
            "UINT64_C(0xfffffe000983f988)",
            "UINT64_C(0xfffffe000983f981)",
            "UINT64_C(0xfffffe000983f960)",
            "UINT64_C(0xfffffe000983f964)",
            "CNDThreadCallPACReuseX0Canary",
            "CNDMkTimerTCQueueOffset",
        ):
            self.assertIn(witness, source)

        self.assertIn("CNDLabThreadCallPACBoundaryModePACReuseDispatch", source)
        self.assertIn('report[@"exactPACReuseAdapterSource"]', source)
        self.assertIn('report[@"exactPACReuseTargetSource"]', source)
        self.assertIn(
            'report[@"exactPACReuseReadOnlyTargetGates"]', source,
        )
        self.assertIn('report[@"pacReuseTransplantVerified"]', source)
        self.assertIn('report[@"pacReuseQueueDrained"]', source)
        self.assertIn('report[@"pacReuseFieldsRestored"]', source)
        self.assertIn('report[@"pacReuseOwnerStateRepaired"]', source)
        self.assertIn('report[@"exactPACReuseDispatch"]', source)
        self.assertIn("pacReuseParam1Address, &signedTarget", source)
        self.assertIn("pacReuseCallbackAddress, &signedAdapter", source)
        self.assertIn(
            "pacReuseParam0Address,\n                    &CNDThreadCallPACReuseX0Canary",
            source,
        )
        self.assertIn("timerObject + CNDMkTimerActiveOffset", source)
        self.assertIn('report[@"timerDestroySkipped"]', source)
        self.assertNotIn("cnd_lab_kernel_call(", source)
        self.assertIn(
            "CNDLabThreadCallPACBoundaryRunPACReuseDispatch(", settings,
        )
        self.assertIn(
            "repairs only the unsigned active count", settings,
        )

    def test_vm_pm_callout_harvest_is_exact_and_restoring(self) -> None:
        source = (
            ROOT / "Cyanide/CNDLabThreadCallPACBoundary.m"
        ).read_text(encoding="utf-8")
        header = (
            ROOT / "Cyanide/CNDLabThreadCallPACBoundary.h"
        ).read_text(encoding="utf-8")
        settings = (
            ROOT / "Cyanide/SettingsViewController.m"
        ).read_text(encoding="utf-8")

        for witness in (
            "CNDStaticRootDomainGlobal",
            "UINT64_C(0xfffffe0009816ce0)",
            "CNDStaticPMDriverCallout",
            "UINT64_C(0xfffffe00081ddc40)",
            "CNDPMDriverCallBusyMask = 0x0200",
            "CNDPMDriverCallReasonSetPowerState = 2",
            "CNDPMOperationListHeadOffset = UINT64_C(0x230)",
            "CNDPMOperationListTailOffset = UINT64_C(0x238)",
            "CNDPMOperationTargetOffset = UINT64_C(0x20)",
            'report[@"exactPMSource"]',
            'report[@"stagedExactly"]',
            'report[@"pmCompletionObserved"]',
            'report[@"pmStateRestored"]',
            'report[@"timerFieldsRestored"]',
            'report[@"exactPMCalloutDispatch"]',
            "CNDLabThreadCallPMCalloutHarvestRunOnce",
            'report[@"operationTranslationObserved"]',
            'report[@"operationRawIAZeroTarget"]',
            'report[@"operationIAZeroTarget"]',
            'report[@"operationTargetMatchesSelectedMethod"]',
        ):
            self.assertIn(witness, source)

        self.assertIn("confirmed == candidate", source)
        self.assertIn("candidateDriver == selectedDriver", source)
        self.assertIn("candidateTarget == expectedSelectedMethod", source)

        self.assertIn(
            "CNDLabThreadCallPACBoundaryRunPMCalloutHarvest", header,
        )
        self.assertIn(
            "CNDLabThreadCallPACBoundaryRunPMCalloutHarvest(", settings,
        )
        self.assertIn("Run PM Harvest", settings)
        self.assertNotIn("cnd_lab_kernel_call(", source)

    def fixture(self, directory: str) -> tuple[Path, Path, str]:
        root = Path(directory)
        kernel = root / "com.apple.kernel"
        snapshot = root / "thread-call.json"
        kernel.write_bytes(b"exact-kernel-fixture")
        callers = [
            {
                "address": address,
                "body": {"ranges": [{"start": address, "end": end}]},
            }
            for address, end in sorted(inventory.REA_CALLERS)
        ]
        references = [
            {
                "source_address": source,
                "source_procedure": {"address": caller},
                "target_address": inventory._hex(inventory.INVOKE_HELPER),
                "kind": {"call": True},
            }
            for source, caller in sorted(inventory.REA_CALLS)
        ]
        snapshot.write_text(json.dumps({
            "target": {"sha256": inventory.KERNEL_SHA256},
            "evidence_bundle": {"records": [{
                "operation": "analyze_function",
                "parameters": {"procedure": inventory._hex(inventory.INVOKE_HELPER)},
                "evidence_id": inventory.INVOKE_EVIDENCE_ID,
                "normalized_result": {
                    "assembly": list(inventory.REA_ASSEMBLY),
                    "procedure": {
                        "address": inventory._hex(inventory.INVOKE_HELPER),
                        "body": {"ranges": [{
                            "start": inventory._hex(inventory.INVOKE_HELPER),
                            "end": "0xfffffe0007b57e1f",
                        }]},
                    },
                    "callers": callers,
                    "incoming_references": references,
                },
            }]},
        }), encoding="utf-8")
        disassembly = "\n".join(
            f"com.apple.kernel[{inventory._hex(address)}] <+0>: {instruction}"
            for address, instruction in inventory.INSTRUCTION_WITNESSES.items()
        )
        return kernel, snapshot, disassembly

    @staticmethod
    def exact_hash(path: Path) -> str:
        if path.name == "com.apple.kernel":
            return inventory.KERNEL_SHA256
        if path.name == "thread-call.json":
            return inventory.REA_SNAPSHOT_SHA256
        if path.name == "dispatch-report.json":
            return inventory.DISPATCH_REPORT_SHA256
        if path.name == "kdp-witness.json":
            return inventory.KDP_WITNESS_SHA256
        raise AssertionError(path)

    def dispatch_fixture(self, directory: str) -> tuple[Path, Path]:
        root = Path(directory)
        report_path = root / "dispatch-report.json"
        witness_path = root / "kdp-witness.json"
        slide = 0x3D1E0000
        adapter = inventory.BRAAZ_ADAPTER + slide
        target = inventory.PAC_REUSE_TARGET + slide
        adapter_signed = "0x60ba7e0045280710"
        target_signed = "0xbba1fe004501613c"
        canary = inventory._hex(inventory.PAC_REUSE_X0_CANARY)
        report = {
            "kernelUUID": inventory.KERNEL_UUID,
            "kernelSlide": inventory._hex(slide),
            "result": "exact-two-stage-pac-reuse-dispatch-observed",
            "mode": "two-stage-pac-reuse-dispatch",
            "exactPACReuseAdapterSource": True,
            "exactPACReuseTargetSource": True,
            "exactPACReuseReadOnlyTargetGates": True,
            "pacReuseTransplantVerified": True,
            "exactPACReuseDispatch": True,
            "callbackDispatched": True,
            "callbackCompleted": True,
            "pacReuseQueueDrained": True,
            "pacReuseReadOnlyTargetGatesStable": True,
            "pacReuseFieldsRestored": True,
            "pacReuseExactPostDispatchOwnerState": True,
            "pacReuseDestroyableOwnerState": True,
            "pacReuseOwnerStateRepaired": True,
            "restoreVerifiedBeforeDestroy": True,
            "timerQuiescedAfterDispatch": True,
            "timerQuiescedBeforeDestroy": 1,
            "timerDestroyed": 1,
            "destroyKR": 0,
            "timerDestroySkipped": 0,
            "usedKernelCall": False,
            "usedKernelWrite": True,
            "pacReuseSettledTCQueue": inventory._hex(0),
            "pacReuseSettledIsArmed": 1,
            "pacReuseSettledActive": 1,
            "pacReusePostCancelTCQueue": inventory._hex(0),
            "pacReusePostCancelIsArmed": 0,
            "pacReusePostCancelActive": 1,
            "pacReuseCleanupOwnerQueue": inventory._hex(0),
            "pacReuseCleanupOwnerIsArmed": 0,
            "pacReuseCleanupOwnerActive": 0,
            "pacReuseAdapter": inventory._hex(adapter),
            "pacReuseTarget": inventory._hex(target),
            "pacReuseX0Canary": canary,
            "pacReuseTransplantedParam0": canary,
            "pacReuseAdapterSigned": adapter_signed,
            "pacReuseTransplantedCallback": adapter_signed,
            "pacReuseTargetSigned": target_signed,
            "pacReuseTransplantedParam1": target_signed,
        }
        for name, static_address in (
            ("Gate", inventory.PAC_REUSE_GATE),
            ("Activation0", inventory.PAC_REUSE_ACTIVATION0),
            ("Activation1", inventory.PAC_REUSE_ACTIVATION1),
        ):
            report[f"pacReuse{name}Address"] = inventory._hex(
                static_address + slide,
            )
            report[f"pacReuse{name}"] = 0
            report[f"pacReuseSettled{name}"] = 0
        report_path.write_text(json.dumps(report), encoding="utf-8")

        witness_path.write_text(json.dumps({
            "result": "exact-live-target-entry-observed",
            "kernel": {
                "uuid": inventory.KERNEL_UUID,
                "sha256": inventory.KERNEL_SHA256,
                "slide": inventory._hex(slide),
            },
            "breakpoint": {
                "kind": "hardware-one-shot",
                "staticTarget": inventory._hex(inventory.PAC_REUSE_TARGET),
                "liveTarget": inventory._hex(target),
                "hit": True,
            },
            "registersAtTargetEntry": {
                "x0": canary,
                "x1": target_signed,
                "pc": inventory._hex(target),
                "lr": inventory._hex(inventory.PAC_REUSE_RETURN_SITE + slide),
                "lrStatic": inventory._hex(inventory.PAC_REUSE_RETURN_SITE),
            },
            "targetGatesAtEntry": {
                "gate": {
                    "liveAddress": inventory._hex(inventory.PAC_REUSE_GATE + slide),
                    "value": "0x00",
                },
                "activation0": {
                    "liveAddress": inventory._hex(
                        inventory.PAC_REUSE_ACTIVATION0 + slide,
                    ),
                    "value": "0x00",
                },
                "activation1": {
                    "liveAddress": inventory._hex(
                        inventory.PAC_REUSE_ACTIVATION1 + slide,
                    ),
                    "value": "0x00",
                },
                "readOnlyEarlyReturnSelected": True,
            },
            "pacReuse": {
                "adapterStatic": inventory._hex(inventory.BRAAZ_ADAPTER),
                "adapterLive": inventory._hex(adapter),
                "adapterSigned": adapter_signed,
                "adapterInstruction": "braaz x1",
                "targetSigned": target_signed,
            },
            "appReport": {
                "sha256": inventory.DISPATCH_REPORT_SHA256,
                "result": "exact-two-stage-pac-reuse-dispatch-observed",
                "fieldsRestored": True,
                "ownerStateRepaired": True,
                "timerDestroyed": True,
                "usedKernelCall": False,
            },
        }), encoding="utf-8")
        return report_path, witness_path

    def test_exact_static_inventory_reports_constrained_lane(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kernel, snapshot, disassembly = self.fixture(directory)
            with mock.patch.object(
                inventory, "sha256", side_effect=self.exact_hash,
            ):
                result = inventory.build_inventory(
                    kernel, snapshot, disassembly_text=disassembly,
                )
        self.assertEqual(
            result["thread_call_abi"]["callback_discriminator"], "0x73d8",
        )
        self.assertEqual(
            result["pac_reuse_chain"]["stage_1"]["instruction"], "braaz x1",
        )
        self.assertFalse(result["pac_reuse_chain"]["arbitrary_kcall"])
        self.assertFalse(result["live"]["observed"])
        self.assertFalse(result["dispatch_proof"]["observed"])

    def test_dispatch_proof_reconciles_app_and_kdp_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kernel, snapshot, disassembly = self.fixture(directory)
            report, witness = self.dispatch_fixture(directory)
            with mock.patch.object(
                inventory, "sha256", side_effect=self.exact_hash,
            ):
                result = inventory.build_inventory(
                    kernel,
                    snapshot,
                    disassembly_text=disassembly,
                    dispatch_report=report,
                    kdp_witness=witness,
                )
        proof = result["dispatch_proof"]
        self.assertTrue(proof["observed"])
        self.assertEqual(
            proof["controlled_x0"],
            inventory._hex(inventory.PAC_REUSE_X0_CANARY),
        )
        self.assertTrue(proof["fields_restored"])
        self.assertFalse(proof["used_kernel_call"])
        self.assertTrue(any(
            "reached the exact target PC with controlled x0" in item
            for item in result["next_boundary"]["proven"]
        ))

    def test_dispatch_register_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, witness = self.dispatch_fixture(directory)
            payload = json.loads(witness.read_text(encoding="utf-8"))
            payload["registersAtTargetEntry"]["x0"] = inventory._hex(0)
            witness.write_text(json.dumps(payload), encoding="utf-8")
            with mock.patch.object(
                inventory, "sha256", side_effect=self.exact_hash,
            ):
                with self.assertRaisesRegex(
                    inventory.InventoryError, "controlled canary",
                ):
                    inventory.verify_dispatch_evidence(report, witness)

    def test_rea_caller_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kernel, snapshot, disassembly = self.fixture(directory)
            payload = json.loads(snapshot.read_text(encoding="utf-8"))
            payload["evidence_bundle"]["records"][0]["normalized_result"][
                "callers"
            ].pop()
            snapshot.write_text(json.dumps(payload), encoding="utf-8")
            with mock.patch.object(
                inventory, "sha256", side_effect=self.exact_hash,
            ):
                with self.assertRaisesRegex(inventory.InventoryError, "caller coverage"):
                    inventory.build_inventory(
                        kernel, snapshot, disassembly_text=disassembly,
                    )

    def test_instruction_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kernel, snapshot, disassembly = self.fixture(directory)
            disassembly = disassembly.replace("braaz x1", "braaz x0")
            with mock.patch.object(
                inventory, "sha256", side_effect=self.exact_hash,
            ):
                with self.assertRaisesRegex(inventory.InventoryError, "witness drifted"):
                    inventory.build_inventory(
                        kernel, snapshot, disassembly_text=disassembly,
                    )

    def test_live_harvest_validates_signed_pointer_identities(self) -> None:
        slide = 0x42C68000
        adapter_object = 0xFFFFFE1E4C003A80
        source_objects = (
            0xFFFFFE1E4C544480,
            0xFFFFFE1E4C1D3080,
            0xFFFFFE1E4C225080,
        )
        memory: dict[int, int] = {
            inventory.BRAAZ_ADAPTER_OBJECT_GLOBAL + slide: adapter_object,
            adapter_object + inventory.THREAD_CALL_FUNC_OFFSET:
                0xA998FE004AD08710,
        }
        for source, object_address, signed in zip(
            inventory.IA_ZERO_SOURCES,
            source_objects,
            (
                0xB2C87E004AA9E13C,
                0xF4CFFE004AB8A0AC,
                0xA5A5FE004AAB3A38,
            ),
        ):
            memory[int(source["object_global"]) + slide] = object_address
            memory[object_address + int(source["field_offset"])] = signed

        def read_bytes(_port: int, address: str, length: int) -> bytes:
            self.assertEqual(length, 8)
            return memory[int(address, 16)].to_bytes(8, "little")

        with mock.patch.object(
            inventory, "debugger_kernel_address",
            return_value=(inventory._hex(inventory.STATIC_TEXT + slide),
                          inventory.KERNEL_UUID),
        ), mock.patch.object(
            inventory, "debugger_kernel_bytes", side_effect=read_bytes,
        ):
            result = inventory.observe_live(62139)
        self.assertTrue(result["observed"])
        self.assertTrue(result["braaz_adapter_source"]["verified"])
        self.assertEqual(len(result["ia_zero_sources"]), 3)
        self.assertTrue(all(item["verified"] for item in result["ia_zero_sources"]))

    def test_live_target_mismatch_fails_closed(self) -> None:
        slide = 0x42C68000
        adapter_object = 0xFFFFFE1E4C003A80
        memory = {
            inventory.BRAAZ_ADAPTER_OBJECT_GLOBAL + slide: adapter_object,
            adapter_object + inventory.THREAD_CALL_FUNC_OFFSET: 0xA998000012345678,
        }

        def read_bytes(_port: int, address: str, _length: int) -> bytes:
            return memory[int(address, 16)].to_bytes(8, "little")

        with mock.patch.object(
            inventory, "debugger_kernel_address",
            return_value=(inventory._hex(inventory.STATIC_TEXT + slide),
                          inventory.KERNEL_UUID),
        ), mock.patch.object(
            inventory, "debugger_kernel_bytes", side_effect=read_bytes,
        ):
            with self.assertRaisesRegex(inventory.InventoryError, "target drifted"):
                inventory.observe_live(62139)


if __name__ == "__main__":
    unittest.main()
