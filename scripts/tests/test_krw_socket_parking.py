"""Structural checks for safe parking of the persistent ICMPv6 KRW sockets."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class KRWSocketParkingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = (ROOT / "Cyanide/kexploit/kexploit_opa334.h").read_text()
        cls.exploit = (ROOT / "Cyanide/kexploit/kexploit_opa334.m").read_text()
        cls.persistence = (ROOT / "Cyanide/kexploit/persistence.m").read_text()
        cls.settings = (ROOT / "Cyanide/SettingsViewController.m").read_text()

    def function_body(self, start_marker: str, end_marker: str) -> str:
        start = self.exploit.index(start_marker)
        end = self.exploit.index(end_marker, start)
        return self.exploit[start:end]

    def persistence_function_body(self, start_marker: str, end_marker: str) -> str:
        start = self.persistence.index(start_marker)
        end = self.persistence.index(end_marker, start)
        return self.persistence[start:end]

    def test_snapshot_preserves_complete_rw_filter_region(self) -> None:
        self.assertIn("uint8_t rwState[EARLY_KRW_LENGTH]", self.header)
        self.assertIn("bool rwStateComplete", self.header)
        self.assertIn(
            "off_inpcb_inp_depend6_inp6_icmp6filt + EARLY_KRW_LENGTH",
            self.exploit,
        )
        self.assertIn("memcpy(rwOrigState,", self.exploit)
        self.assertIn("sizeof(rwOrigState)", self.exploit)
        unavailable = self.exploit.index(
            "restore snapshot unavailable: rw PCB not in OOB window"
        )
        self.assertIn("return -1;", self.exploit[unavailable:unavailable + 160])

    def test_parking_is_bounded_and_restores_the_complete_snapshot(self) -> None:
        park = self.function_body(
            "static bool krw_park_rw_socket_locked(void)",
            "static bool krw_verify_rw_socket_parked_locked(void)",
        )
        self.assertIn("KRW_PARK_RETRY_LIMIT 3", self.exploit)
        self.assertIn("attempt < KRW_PARK_RETRY_LIMIT", park)
        self.assertIn("gKrwRestoreSnapshot.rwState", park)
        self.assertIn("sizeof(gKrwRestoreSnapshot.rwState)", park)

    def test_every_native_read_and_write_parks_before_unlock(self) -> None:
        read = self.function_body(
            "static bool early_kread_checked", "static bool early_kread64_checked"
        )
        write = self.function_body(
            "static bool early_kwrite32bytes_checked",
            "static bool early_kwrite64_checked",
        )
        for body in (read, write):
            with self.subTest(operation=body.splitlines()[0]):
                park = body.index("krw_park_rw_socket_locked()")
                unlock = body.index("pthread_mutex_unlock(&krwLock)", park)
                self.assertLess(park, unlock)
                self.assertIn("krw_verify_rw_socket_parked_locked()", body)
                self.assertIn("parked && parkVerified", body)

    def test_readiness_repairs_stale_recovered_state_and_verifies_final_park(self) -> None:
        ready = self.function_body(
            "bool kexploit_krw_ready(void)", "bool kexploit_terminal_cleanup(void)"
        )
        self.assertIn("early_kread64_checked(g_kernel_base, &magic)", ready)
        checked_read = self.function_body(
            "static bool early_kread_checked", "static bool early_kread64_checked"
        )
        target = checked_read.index("set_target_kaddr_locked(where)")
        self.assertGreater(checked_read.index("krw_park_rw_socket_locked()"), target)
        self.assertIn("krw_verify_rw_socket_parked_locked()", checked_read)

    def test_terminal_cleanup_uses_verified_park_not_partial_zero_fill(self) -> None:
        cleanup = self.function_body(
            "bool kexploit_terminal_cleanup(void)", "void early_kread(uint64_t where"
        )
        self.assertIn("krw_park_rw_socket_locked()", cleanup)
        self.assertIn("krw_verify_rw_socket_parked_locked()", cleanup)
        self.assertNotIn("uint8_t rwRestore", cleanup)
        self.assertNotIn("memset(rwRestore", cleanup)
        # The forged control pair is preserved only when launchd holds the
        # ports; otherwise the cleanup rolls the control PCB back after the
        # verified park, so the park must come before any rollback write.
        self.assertIn("krw_persistence_launchd_holds_krw()", cleanup)
        # The per-process flag alone is not enough: transfer_to_launchd resets
        # it at entry, so a failed re-anchor must not un-forge a launchd-held
        # pair. The durable saved record gates the rollback too.
        self.assertIn("krw_persistence_has_saved_recovery()", cleanup)
        park = cleanup.index("krw_park_rw_socket_locked()")
        rollback = cleanup.index("gKrwRestoreSnapshot.controlCksum")
        self.assertLess(park, rollback)
        self.assertIn("launchd-holds=%d", cleanup)

    def test_terminal_cleanup_never_unforges_a_launchd_anchored_pair(self) -> None:
        cleanup = self.function_body(
            "bool kexploit_terminal_cleanup(void)", "void early_kread(uint64_t where"
        )
        gate = cleanup[cleanup.index("bool launchdHolds"):]
        gate = gate[:gate.index("pthread_mutex_lock")]
        self.assertIn("krw_persistence_launchd_holds_krw()", gate)
        self.assertIn("krw_persistence_has_saved_recovery()", gate)

    def test_failed_reanchor_preserves_launchd_held_flag(self) -> None:
        transfer = self.persistence_function_body(
            "bool krw_persistence_transfer_to_launchd(void)", "\nbool "
        )
        self.assertIn("bool previouslyHeld = gKRWPersistenceLaunchdHoldsKrw", transfer)
        self.assertIn(
            "gKRWPersistenceLaunchdHoldsKrw = launchdWorkComplete || previouslyHeld",
            transfer,
        )

    def test_dead_recovered_pair_preserves_record_and_blocks_fresh_acquisition(self) -> None:
        recover = self.persistence_function_body(
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)",
            "\nbool krw_persistence_recover(void)",
        )
        self.assertIn("if (!kexploit_krw_ready())", recover)
        branch = recover[
            recover.index("if (!kexploit_krw_ready())"):
            recover.index("uint64_t launchdProc")
        ]
        # Probe liveness BEFORE clearing recovered fds, then branch on it.
        probe = branch.index("kexploit_control_socket_parkable()")
        clear = branch.index("persist_clear_recovered_kernel_state()")
        self.assertLess(probe, clear)
        self.assertIn("CNDKRWPersistenceRecoveryRetryableFailure", branch)
        self.assertNotIn("CNDKRWPersistenceRecoveryStaleRecord", branch)
        self.assertNotIn("persist_forget_saved_primitive", self.persistence)
        self.assertIn(
            "preserving the record and refusing fresh acquisition", branch
        )
        # The park-probe helper exists and is exported.
        self.assertIn("bool kexploit_control_socket_parkable(void)", self.exploit)
        self.assertIn("bool kexploit_control_socket_parkable(void);", self.header)
        probe_body = self.function_body(
            "bool kexploit_control_socket_parkable(void)",
            "static bool cnd_park_committed_primitive",
        )
        self.assertIn("pthread_mutex_lock(&krwLock)", probe_body)
        self.assertIn("krw_park_rw_socket_locked()", probe_body)
        self.assertIn("krw_verify_rw_socket_parked_locked()", probe_body)

    def test_termination_quiesce_closes_admission_and_parks_under_krw_lock(self) -> None:
        quiesce = self.function_body(
            "bool kexploit_quiesce_for_process_termination(void)",
            "bool kexploit_terminal_cleanup(void)",
        )
        gate = quiesce.index(
            "atomic_store_explicit(&gKrwTerminationQuiescing, true"
        )
        lock = quiesce.index("pthread_mutex_lock(&krwLock)")
        park = quiesce.index("krw_park_rw_socket_locked()", lock)
        verify = quiesce.index("krw_verify_rw_socket_parked_locked()", park)
        unlock = quiesce.index("pthread_mutex_unlock(&krwLock)", verify)
        self.assertLess(gate, lock)
        self.assertLess(lock, park)
        self.assertLess(park, verify)
        self.assertLess(verify, unlock)
        self.assertNotIn("early_kwrite64_checked", quiesce)
        self.assertNotIn("controlCksum", quiesce)
        self.assertNotIn("krw_write64_and_park_locked", quiesce)

    def test_checked_operations_recheck_termination_gate_after_lock(self) -> None:
        for start, end in (
            ("static bool early_kread_checked", "static bool early_kread64_checked"),
            ("static bool early_kwrite32bytes_checked", "static bool early_kwrite64_checked"),
        ):
            body = self.function_body(start, end)
            lock = body.index("pthread_mutex_lock(&krwLock)")
            gate = body.index("gKrwTerminationQuiescing", lock)
            target = body.index("set_target_kaddr_locked", gate)
            self.assertLess(lock, gate)
            self.assertLess(gate, target)

    def test_busy_termination_uses_primitive_barrier_instead_of_skipping(self) -> None:
        start = self.settings.index(
            "void settings_best_effort_termination_cleanup(const char *reason)"
        )
        end = self.settings.index(
            "void settings_destroy_springboard_remote_call_sync(void)", start
        )
        cleanup = self.settings[start:end]
        timeout = cleanup.index("if (!locked)")
        quiesce = cleanup.index(
            "kexploit_quiesce_for_process_termination()", timeout
        )
        early_return = cleanup.index("return;", quiesce)
        self.assertLess(timeout, quiesce)
        self.assertLess(quiesce, early_return)
        self.assertNotIn(
            "Last-chance cleanup skipped because another operation is still active",
            cleanup,
        )

    def test_persistence_requires_a_complete_version_two_snapshot(self) -> None:
        self.assertIn('@"Version": @2', self.persistence)
        self.assertIn('@"RestoreRWState"', self.persistence)
        self.assertIn("restoreSnapshot.rwStateComplete = true", self.persistence)
        self.assertIn("persist_primitive_has_complete_restore_state", self.persistence)
        self.assertIn('unsupported or incomplete "\n               "restore snapshot', self.persistence)
        self.assertNotIn("recovered legacy partial KRW restore snapshot", self.persistence)
        self.assertIn("kexploit_krw_restore_snapshot_import(&restoreSnapshot)", self.persistence)

    def test_socket_parking_never_writes_a_partial_snapshot(self) -> None:
        park = self.function_body(
            "static bool krw_park_rw_socket_locked(void)",
            "static bool krw_verify_rw_socket_parked_locked(void)",
        )
        verify = self.function_body(
            "static bool krw_verify_rw_socket_parked_locked(void)",
            "bool kexploit_krw_ready(void)",
        )
        self.assertIn("!gKrwRestoreSnapshot.rwStateComplete", park)
        self.assertIn("!gKrwRestoreSnapshot.rwStateComplete", verify)
        self.assertNotIn("2 * sizeof(uint64_t)", verify)

    def test_snapshot_import_rejects_non_kernel_pointers(self) -> None:
        # The park writes rwState back through the forged control filter, so
        # an imported snapshot whose control filter or restored rw filter is
        # not a kernel pointer would turn the park into a wild write.
        imported = self.function_body(
            "void kexploit_krw_restore_snapshot_import",
            "bool kexploit_krw_restore_snapshot_export",
        )
        self.assertIn("!snapshot->rwStateComplete", imported)
        self.assertIn("is_kaddr_valid(snapshot->controlFilter)", imported)
        self.assertIn("is_kaddr_valid(rwFilter)", imported)
        self.assertIn("kexploit_krw_restore_snapshot_clear()", imported)

    def test_persistence_requires_root_token_before_registering_fileports(self) -> None:
        transfer = self.persistence_function_body(
            "bool krw_persistence_transfer_to_launchd(void)",
            "static bool persist_consume_saved_token",
        )
        root_token = transfer.index("persist_issue_file_token")
        fileports = transfer.index("fileport_makeport")
        register = transfer.index("bootstrap_register")
        save = transfer.index("persist_save_primitive")
        self.assertLess(root_token, fileports)
        self.assertLess(root_token, register)
        self.assertLess(root_token, save)
        self.assertIn('setObject:rootToken forKey:kLaunchdRootFileTokenDefaultsKey', self.persistence)
        self.assertIn('BOOL synchronized = [defaults synchronize]', self.persistence)
        self.assertIn('failed to durably save complete KRW recovery record', self.persistence)
        self.assertIn('Anchor result: %s stage=%s', transfer)

    def test_launchd_registers_rw_socket_before_forged_control_socket(self) -> None:
        transfer = self.persistence_function_body(
            "bool krw_persistence_transfer_to_launchd(void)",
            "static bool persist_consume_saved_token",
        )
        rw_register = transfer.index(
            "bootstrap_register(bootstrap_port, rwPortName, rwPort)"
        )
        control_register = transfer.index(
            "bootstrap_register(bootstrap_port, controlPortName, controlPort)"
        )
        self.assertLess(rw_register, control_register)
        self.assertIn("launchd retains the pointee socket", transfer)

    def test_launchd_persistence_uses_exact_identity_single_thread_bootstrap(self) -> None:
        transfer = self.persistence_function_body(
            "bool krw_persistence_transfer_to_launchd(void)",
            "static bool persist_consume_saved_token",
        )
        self.assertIn(
            'init_remote_call_identity_bootstrap_original_thread_only(\n'
            '            "launchd", kLaunchdIdentityBootstrapTimeoutMS)',
            transfer,
        )
        self.assertNotIn('init_remote_call("launchd"', transfer)
        self.assertIn("kLaunchdIdentityBootstrapTimeoutMS = 15000", self.persistence)

        for exact_identity_field in (
            "identityBootstrapRequested",
            "identityMessageValid",
            "identityThreadRightExact",
            "identityTaskRightExact",
            "identityHandlerRetained",
            "identityInitialConversionSucceeded",
            "identityInitialReplySucceeded",
        ):
            self.assertIn(f"launchdSnapshot.{exact_identity_field}", transfer)
        self.assertIn("launchdSnapshot.pid != 1", transfer)

    def test_persistence_is_saved_before_launchd_teardown(self) -> None:
        transfer = self.persistence_function_body(
            "bool krw_persistence_transfer_to_launchd(void)",
            "static bool persist_consume_saved_token",
        )
        save = transfer.index("ok = persist_save_primitive")
        teardown = transfer.index("int teardownResult = destroy_remote_call()")
        teardown_check = transfer.index("if (teardownResult != 0)", teardown)
        self.assertLess(save, teardown)
        self.assertLess(teardown, teardown_check)
        self.assertNotIn("launchdWorkComplete = false", transfer[teardown_check:])
        self.assertIn("durable recovery metadata are retained", transfer)
        self.assertIn("if (!remote_call_current_success())", transfer)
        self.assertNotIn("\n    destroy_remote_call();", transfer)

    def test_recovery_is_tri_state_and_never_erases_same_boot_record(self) -> None:
        self.assertIn("CNDKRWPersistenceRecoveryRetryableFailure", self.persistence)
        self.assertIn("CNDKRWPersistenceRecoveryStaleRecord", self.persistence)
        recover = self.persistence[self.persistence.index(
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)"
        ):]
        self.assertNotIn("removeObjectForKey:kKRWPrimitiveDefaultsKey", recover)
        self.assertNotIn("removeObjectForKey:kLaunchdRootFileTokenDefaultsKey", recover)
        self.assertIn("kCNDBootstrapUnknownService", recover)
        self.assertIn("preserving the record and refusing fresh acquisition", recover)
        self.assertIn('primitive[@"BootIdentity"] = bootIdentity', self.persistence)

    def test_time_boot_identity_detects_reboot_with_fractional_tolerance(self) -> None:
        relationship = self.persistence_function_body(
            "persist_primitive_boot_identity_relationship(NSDictionary *primitive)",
            "static bool persist_primitive_has_complete_restore_state",
        )
        self.assertIn('hasPrefix:@"uuid:"', relationship)
        self.assertIn('hasPrefix:@"time:"', relationship)
        self.assertIn("fabs(savedEpoch - currentEpoch) <= 5.0", relationship)
        self.assertIn(
            "CNDKRWBootIdentityRelationshipDefinitivelyDifferent",
            relationship,
        )
        self.assertIn(
            "return CNDKRWBootIdentityRelationshipUncertain;",
            relationship,
        )

        recover = self.persistence_function_body(
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)",
            "\nbool krw_persistence_recover(void)",
        )
        definitive = recover.index(
            "CNDKRWBootIdentityRelationshipDefinitivelyDifferent"
        )
        stale = recover.index("CNDKRWPersistenceRecoveryStaleRecord", definitive)
        uncertain = recover.index(
            "CNDKRWBootIdentityRelationshipUncertain", stale
        )
        retryable = recover.index(
            "CNDKRWPersistenceRecoveryRetryableFailure", uncertain
        )
        token = recover.index("persist_consume_saved_token", uncertain)
        lookup = recover.index("bootstrap_look_up", token)
        self.assertLess(definitive, stale)
        self.assertLess(stale, uncertain)
        self.assertLess(uncertain, retryable)
        self.assertLess(retryable, token)
        self.assertLess(token, lookup)
        uncertain_branch = recover[uncertain:token]
        self.assertIn("return CNDKRWPersistenceRecoveryRetryableFailure", uncertain_branch)
        self.assertIn("refusing socket", uncertain_branch)
        self.assertIn("reconstruction or fresh acquisition", uncertain_branch)

        saved = self.persistence_function_body(
            "bool krw_persistence_has_saved_recovery(void)",
            "static bool persist_is_kernel_ptr",
        )
        self.assertIn(
            "CNDKRWBootIdentityRelationshipDefinitivelyDifferent", saved
        )

    def test_transfer_failure_verifies_local_socket_park(self) -> None:
        entry = self.function_body("int kexploit_opa334(void)", "return 0;\n}")
        failure = entry[entry.index("if (!krw_persistence_transfer_to_launchd())") :]
        self.assertIn("cnd_park_committed_primitive()", failure)
        self.assertIn("CNDKExploitOutcomeUnsafeUnverified", failure)
        self.assertIn("persistence_failed_unsafe", failure)
        self.assertIn("persistence_failed_locally_parked", failure)
        self.assertNotIn("Couldn't park state", failure)


if __name__ == "__main__":
    unittest.main()
