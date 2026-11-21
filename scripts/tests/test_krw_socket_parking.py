"""Structural checks for safe parking of the persistent ICMPv6 KRW sockets."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class KRWSocketParkingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = (ROOT / "Cyanide/kexploit/kexploit_opa334.h").read_text()
        cls.persistence_header = (
            ROOT / "Cyanide/kexploit/persistence.h"
        ).read_text()
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

    def settings_function_body(self, start_marker: str, end_marker: str) -> str:
        start = self.settings.index(start_marker)
        end = self.settings.index(end_marker, start)
        return self.settings[start:end]

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

    def test_released_recovered_pair_clears_committed_cleanup_marker(self) -> None:
        release = self.function_body(
            "void kexploit_krw_note_recovered_pair_released(void)",
            "static void cnd_exploit_note_race_attempt(void)",
        )
        self.assertIn(
            "void kexploit_krw_note_recovered_pair_released(void);", self.header
        )
        self.assertIn("CNDExploitCleanupPrimitiveCommitted", release)
        self.assertIn(
            "gExploitCleanupDisposition = CNDExploitCleanupUnmodified;", release
        )
        clear = self.persistence_function_body(
            "static void persist_clear_recovered_kernel_state(void)",
            "static bool persist_validate_recovered_krw(void)",
        )
        self.assertLess(
            clear.index("persist_close_recovered_fds();"),
            clear.index("kexploit_krw_note_recovered_pair_released();"),
        )

    def test_retained_pair_is_kernel_defunct_protected_before_anchor(self) -> None:
        self.assertIn("off_socket_so_flags", self.exploit)
        self.assertIn("CND_SOF_NODEFUNCT 0x00008000U", self.exploit)
        protect = self.function_body(
            "static bool krw_socket_nodefunct_state_locked(",
            "static bool krw_pair_nodefunct_state_locked(",
        )
        self.assertIn("pcb + off_inpcb_inp_socket", protect)
        self.assertIn("socketAddress + off_socket_so_flags", protect)
        self.assertIn("regionFlags |= CND_SOF_NODEFUNCT", protect)
        self.assertIn("krw_write32_locked_no_park", protect)
        self.assertIn("CND_SOCKET_FLAGS_WRITE_PREFIX", protect)
        self.assertNotIn("krw_write64_locked_no_park", protect)
        self.assertGreaterEqual(
            protect.count("krw_read_locked_no_park"), 3,
            "the socket pointer, original flags, and written flags must all be read",
        )

        acquisition = self.exploit[
            self.exploit.index("int kexploit_opa334(void)") :
        ]
        retained = acquisition.index("krw_sockets_leak_forever()")
        protected = acquisition.index(
            "kexploit_krw_ensure_defunct_protection()", retained
        )
        anchored = acquisition.index("krw_persistence_transfer_to_launchd()")
        self.assertLess(retained, protected)
        self.assertLess(protected, anchored)

        transfer = self.persistence_function_body(
            "CNDKRWPersistenceTransferResult krw_persistence_transfer_to_launchd(void)",
            "bool krw_persistence_rearm_next_process(",
        )
        self.assertIn("kexploit_krw_defunct_protection_verified()", transfer)
        self.assertIn("socket-nodefunct-preflight", transfer)

    def test_recovery_repairs_defunct_protection_before_admission(self) -> None:
        activation = self.function_body(
            "bool kexploit_krw_activate_recovered_pair(void)",
            "/* Recovery liveness is deliberately tri-state.",
        )
        self.assertIn("kexploit_krw_ensure_defunct_protection()", activation)
        self.assertIn('"recovery-nodefunct"', activation)
        self.assertIn("verified = verified && defunctProtected", activation)

        ready = self.function_body(
            "bool kexploit_krw_ready(void)",
            "bool kexploit_recoverable_termination_armed(void)",
        )
        self.assertIn("kexploit_krw_defunct_protection_verified()", ready)
        self.assertIn('"socket-nodefunct"', ready)

    def test_socket_flags_offset_is_anchored_to_supported_layout(self) -> None:
        offsets_header = (ROOT / "Cyanide/kexploit/offsets.h").read_text()
        offsets_source = (ROOT / "Cyanide/kexploit/offsets.m").read_text()
        self.assertIn("extern uint32_t off_socket_so_flags;", offsets_header)
        self.assertIn("uint32_t off_socket_so_flags = 0;", offsets_source)
        self.assertIn(
            "off_socket_so_usecount - 3 * (uint32_t)sizeof(uint32_t)",
            offsets_source,
        )

    def test_parking_is_bounded_and_restores_the_complete_snapshot(self) -> None:
        park = self.function_body(
            "static bool krw_park_rw_socket_locked(void)",
            "static bool krw_verify_canonical_pair_parked_locked",
        )
        self.assertIn("KRW_PARK_RETRY_LIMIT 3", self.exploit)
        self.assertIn("attempt < KRW_PARK_RETRY_LIMIT", park)
        self.assertIn("setsockopt(controlSocket, IPPROTO_ICMPV6, ICMP6_FILTER", park)
        self.assertIn("gKrwRestoreSnapshot.rwState", park)
        self.assertIn("sizeof(gKrwRestoreSnapshot.rwState)", park)
        self.assertNotIn("set_target_kaddr_locked", park)
        self.assertNotIn("setsockopt(rwSocket", park)
        self.assertNotIn("controlCksum", park)

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

    def test_readiness_uses_checked_read_and_reparks(self) -> None:
        ready = self.function_body(
            "bool kexploit_krw_ready(void)",
            "bool kexploit_recoverable_termination_armed(void)",
        )
        self.assertIn("early_kread64_checked(g_kernel_base, &magic)", ready)
        self.assertNotIn("setsockopt(controlSocket", ready)
        self.assertNotIn("getsockopt(rwSocket", ready)

    def test_recovery_activates_complete_forged_pair_before_readiness(self) -> None:
        activation = self.function_body(
            "bool kexploit_krw_activate_recovered_pair(void)",
            "/* Recovery liveness is deliberately tri-state.",
        )
        self.assertIn(
            "bool kexploit_krw_activate_recovered_pair(void);", self.header
        )
        self.assertIn("observedChecksum == 0", activation)
        self.assertIn(
            "observedChecksum == gKrwRestoreSnapshot.controlCksum", activation
        )
        self.assertIn(
            "krw_restore_recoverable_control_checksum_locked()", activation
        )
        self.assertIn("krw_verify_canonical_pair_parked_locked(&proof)", activation)
        self.assertIn("krw_park_rw_socket_locked()", activation)

        recover = self.persistence_function_body(
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)",
            "\nbool krw_persistence_recover(void)",
        )
        imported = recover.index(
            "kexploit_krw_restore_snapshot_import(&restoreSnapshot)"
        )
        activated = recover.index("kexploit_krw_activate_recovered_pair()")
        ready = recover.index("kexploit_krw_ready()", activated)
        self.assertLess(imported, activated)
        self.assertLess(activated, ready)

    def test_terminal_cleanup_uses_verified_park_not_partial_zero_fill(self) -> None:
        cleanup = self.function_body(
            "bool kexploit_terminal_cleanup_with_disposition(",
            "bool kexploit_terminal_cleanup(void)",
        )
        self.assertIn("krw_park_rw_socket_locked()", cleanup)
        self.assertIn("krw_verify_rw_socket_parked_locked()", cleanup)
        self.assertNotIn("uint8_t rwRestore", cleanup)
        self.assertNotIn("memset(rwRestore", cleanup)
        # A recoverable handoff parks the RW socket while keeping the forged
        # control link and restoring the October checksum state. With no
        # holder, cleanup later restores both original control fields.
        self.assertIn("krw_persistence_launchd_holds_krw()", cleanup)
        # The per-process flag alone is not enough: transfer_to_launchd resets
        # it at entry, so a failed re-anchor must not un-forge a launchd-held
        # pair. The durable saved record gates the rollback too.
        self.assertIn("krw_persistence_has_saved_recovery()", cleanup)
        recoverable_finalize = cleanup[
            cleanup.index("bool parked = armed;"):
            cleanup.index("bool rolledBack = false;")
        ]
        self.assertIn(
            "krw_restore_recoverable_control_checksum_locked()",
            recoverable_finalize,
        )
        self.assertIn(
            "krw_verify_canonical_pair_parked_locked(&parkProof)",
            recoverable_finalize,
        )
        self.assertIn("launchd-may-hold=%d", cleanup)
        self.assertIn("recovery-proven=%d", cleanup)

    def test_recoverable_parking_restores_october_control_checksum(self) -> None:
        self.assertNotIn("krw_park_original_anchored_pair_locked", self.exploit)
        park = self.function_body(
            "static bool krw_park_rw_socket_locked(void) {",
            "static bool krw_verify_canonical_pair_parked_locked",
        )
        verify = self.function_body(
            "static bool krw_verify_canonical_pair_parked_locked(",
            "static bool krw_verify_rw_socket_parked_locked(void)",
        )
        self.assertNotIn("gKrwRestoreSnapshot.controlCksum", park)
        self.assertNotIn("set_target_kaddr_locked", park)
        self.assertNotIn("setsockopt(rwSocket", park)
        self.assertNotIn("getsockopt(rwSocket", park)
        self.assertIn("setsockopt(controlSocket", park)
        self.assertIn("krw_read_locked_no_park", verify)
        self.assertIn("gKrwRestoreSnapshot.controlCksum", verify)
        self.assertIn("observedControlLink", verify)
        self.assertIn("observedControlChecksum", verify)
        self.assertIn(
            "observedControlChecksum == gKrwRestoreSnapshot.controlCksum",
            verify,
        )
        self.assertIn("krw_verify_rw_socket_readback_locked()", verify)

        cleanup = self.function_body(
            "bool kexploit_terminal_cleanup_with_disposition(",
            "bool kexploit_terminal_cleanup(void)",
        )
        prepare = self.function_body(
            "bool kexploit_prepare_recoverable_termination(",
            "bool kexploit_quiesce_for_process_termination(void)",
        )
        self.assertIn("statePresent && krw_park_rw_socket_locked()", prepare)
        self.assertIn(
            "krw_restore_recoverable_control_checksum_locked()", prepare
        )
        self.assertLess(
            prepare.index("statePresent && krw_park_rw_socket_locked()"),
            prepare.index("gKrwRecoverableTerminationArmed, true"),
        )
        recoverable_finalize = cleanup[
            cleanup.index("bool parked = armed;"):
            cleanup.index("bool rolledBack = false;")
        ]
        self.assertIn("parked = krw_park_rw_socket_locked();", recoverable_finalize)
        self.assertIn(
            "krw_restore_recoverable_control_checksum_locked()",
            recoverable_finalize,
        )
        rollback = cleanup[cleanup.index("bool rolledBack = false;"):]
        self.assertIn("gKrwRestoreSnapshot.controlCksum", rollback)
        self.assertIn("gKrwRestoreSnapshot.controlFilter", rollback)
        self.assertIn("bool parked = armed;", cleanup)

    def test_terminal_cleanup_never_unforges_a_launchd_anchored_pair(self) -> None:
        cleanup = self.function_body(
            "bool kexploit_terminal_cleanup_with_disposition(",
            "bool kexploit_terminal_cleanup(void)",
        )
        gate = cleanup[cleanup.index("bool launchdMayHold"):]
        gate = gate[:gate.index("pthread_mutex_lock")]
        self.assertIn("krw_persistence_launchd_holds_krw()", gate)
        self.assertIn("krw_persistence_has_saved_recovery()", gate)
        # The saved record only forbids rollback; it never makes the
        # disposition recoverable. Only the exact anchor proof (or an armed
        # update lease, which required that proof) does.
        recoverable = gate[gate.index("bool recoverable"):gate.index(";")]
        self.assertNotIn("krw_persistence_has_saved_recovery()", recoverable)
        self.assertIn(
            "krw_persistence_verify_current_generation_anchor(&anchor)", gate
        )
        self.assertIn("parked && recoverable", cleanup)
        self.assertIn("CNDKRWTerminationRecoverableAnchored", cleanup)
        self.assertIn("CNDKRWTerminationSafelyRolledBack", cleanup)
        self.assertIn("CNDKRWTerminationUnsafe", cleanup)

    def test_plain_close_uses_the_committed_reusable_grant_pair(self) -> None:
        cleanup = self.function_body(
            "bool kexploit_terminal_cleanup_with_disposition(",
            "bool kexploit_terminal_cleanup(void)",
        )
        self.assertNotIn("krw_persistence_rearm_next_process", cleanup)
        self.assertNotIn("init_remote_call", cleanup)
        self.assertIn("Acquisition commits one reusable next-process bearer pair", cleanup)
        self.assertIn("never opens", cleanup)

    def test_respring_requires_exact_recoverable_anchor_before_cleanup(self) -> None:
        prepare = self.settings_function_body(
            "static BOOL settings_prepare_for_respring_sync(void)",
            "static CNDKRWTerminationDisposition\n"
            "settings_terminal_kexploit_cleanup_sync_internal",
        )
        proof = prepare.index(
            "krw_persistence_verify_current_generation_anchor(&anchor)"
        )
        stop_loops = prepare.index("settings_request_all_live_loops_stop")
        close_fds = prepare.index(
            "kexploit_terminal_cleanup_with_disposition(&disposition)"
        )
        self.assertLess(proof, stop_loops)
        self.assertLess(stop_loops, close_fds)
        self.assertIn("anchor.metadataExact && anchor.fileglobExact", prepare)
        self.assertIn("return NO;", prepare[proof:stop_loops])
        self.assertIn(
            "disposition != CNDKRWTerminationRecoverableAnchored", prepare
        )
        self.assertNotIn("kexploit_terminal_cleanup();", prepare)

        # Every respring entry point must consume the preparation result and
        # must not show the overlay after a refused handoff.
        self.assertEqual(
            self.settings.count("prepared = settings_prepare_for_respring_sync();"),
            3,
        )
        self.assertGreaterEqual(self.settings.count("if (!prepared)"), 3)

    def test_terminal_cleanup_final_filter_restore_never_parks(self) -> None:
        cleanup = self.function_body(
            "bool kexploit_terminal_cleanup_with_disposition(",
            "bool kexploit_terminal_cleanup(void)",
        )
        rollback = cleanup[cleanup.index("if (parked && !rollbackForbidden)"):]
        rollback = rollback[:rollback.index("rolledBack = filterRestored")]
        cksum = rollback.index("gKrwRestoreSnapshot.controlCksum")
        filt = rollback.index("krw_write64_locked_no_park(")
        self.assertLess(cksum, filt)
        self.assertIn("gKrwRestoreSnapshot.controlFilter", rollback[filt:])
        self.assertNotIn("early_kwrite64_checked(\n            controlSocketPcb + off_inpcb_inp_depend6_inp6_icmp6filt", rollback)
        no_park = self.function_body(
            "static bool krw_write32_locked_no_park(",
            "static bool krw_write64_locked_no_park(",
        )
        self.assertNotIn("krw_park_rw_socket_locked", no_park)

    def test_holder_flag_tracks_actual_launchd_work_and_prior_anchor(self) -> None:
        transfer = self.persistence_function_body(
            "CNDKRWPersistenceTransferResult krw_persistence_transfer_to_launchd(void)", "\nstatic bool "
        )
        self.assertIn("previouslyHeld", transfer)
        self.assertIn(
            "gKRWPersistenceLaunchdHoldsKrw = controlRegistered || previouslyHeld",
            transfer,
        )
        self.assertIn("CNDKRWPersistenceTransferCommittedExact", transfer)
        self.assertIn("krw_persistence_verify_current_generation_anchor(", transfer)
        self.assertIn("verification.recordCommitted", transfer)
        self.assertIn("verification.nextProcessArmed", transfer)
        self.assertIn("gKRWNextProcessArmed = exactVerified", transfer)
        verify = self.persistence_function_body(
            "bool krw_persistence_verify_current_generation_anchor(",
            "CNDKRWPersistenceTransferResult krw_persistence_transfer_to_launchd(void)",
        )
        self.assertIn("if (ok) {", verify)
        self.assertIn("gKRWPersistenceLaunchdHoldsKrw = true;", verify)
        self.assertNotIn("gKRWNextProcessArmed = true;", verify)
        self.assertIn("The transfer/rearm owner publishes", verify)
        self.assertIn("gKRWNextProcessArmed", verify)
        self.assertIn("fileport_makefd(controlPort)", verify)
        self.assertIn("persist_fileglob_for_fd(selfProc, controlSocket)", verify)
        self.assertIn("duplicateControlGlob != currentControlGlob", verify)
        self.assertIn("duplicateRWGlob != currentRWGlob", verify)
        self.assertNotIn("sandbox_extension_consume", verify)
        self.assertIn('primitive[@"ControlPortToken"]', verify)
        self.assertIn('primitive[@"RWPortToken"]', verify)

        # PID A gets lookup grants for anchor verification. The tokens saved
        # for PID B are separately issued and never consumed by the
        # pre-termination verifier. The sandbox may deterministically issue
        # identical payload bytes for the same class/name; byte equality is
        # not a reason to reject an otherwise valid launchd anchor.
        current_control = transfer.index("control-current-lookup-token")
        current_rw = transfer.index("rw-current-lookup-token")
        saved_control = transfer.index('failureStage = "control-lookup-token"')
        saved_rw = transfer.index('failureStage = "rw-lookup-token"')
        self.assertLess(current_control, saved_control)
        self.assertLess(current_rw, saved_rw)
        self.assertIn("controlCurrentLookupToken", transfer)
        self.assertIn("rwCurrentLookupToken", transfer)
        self.assertNotIn("lookup-token-separation", transfer)
        self.assertNotIn(
            "strcmp(controlCurrentLookupToken, controlLookupToken)", transfer
        )
        self.assertNotIn("strcmp(rwCurrentLookupToken, rwLookupToken)", transfer)

    def test_recovery_preserves_ambiguous_pairs_and_records_symbolic_failures(self) -> None:
        recover = self.persistence_function_body(
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)",
            "\nbool krw_persistence_recover(void)",
        )
        branch = recover[
            recover.index(
                "if (!recoveredPairActivated || !kexploit_krw_ready())"
            ):
            recover.index("uint64_t launchdProc")
        ]
        capture = branch.index("kexploit_krw_socket_diagnostic()")
        probe = branch.index("kexploit_control_socket_park_probe()")
        clear = branch.index("persist_clear_recovered_kernel_state()", probe)
        alive = branch.index("if (parkProbe == CNDKRWParkProbeAlive)", clear)
        ambiguous = branch.index(
            'printf("[PERSIST] recovered pair failure is not conclusive', alive
        )
        self.assertLess(capture, probe)
        self.assertLess(probe, clear)
        self.assertIn("CNDKRWPersistenceRecoveryRetryableFailure", branch[alive:ambiguous])
        self.assertIn("CNDKRWPersistenceRecoveryRetryableFailure", branch[ambiguous:])
        self.assertIn('"recovered-pair-validation-indeterminate"', branch)
        self.assertNotIn("CNDKRWPersistenceRecoveryStaleRecord", branch)
        self.assertNotIn("persist_release_unusable_same_boot_record", branch)
        self.assertNotIn("persist_forget_saved_primitive", recover)

        probe_body = self.function_body(
            "CNDKRWParkProbeResult kexploit_control_socket_park_probe(void)",
            "bool kexploit_control_socket_parkable(void)",
        )
        self.assertIn("pthread_mutex_lock(&krwLock)", probe_body)
        self.assertIn("krw_park_rw_socket_locked()", probe_body)
        self.assertIn("krw_verify_rw_socket_parked_locked()", probe_body)
        self.assertIn("CNDKRWParkProbeIndeterminate", probe_body)
        self.assertIn("CNDKRWParkProbeAlive", probe_body)
        self.assertNotIn("CNDKRWParkProbeDead", probe_body)
        self.assertNotIn("definitiveFailure", probe_body)
        self.assertIn(
            "CNDKRWParkProbeResult kexploit_control_socket_park_probe(void);",
            self.header,
        )
        finish = self.persistence_function_body(
            "static CNDKRWPersistenceRecoveryResult persist_finish_recovery(",
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)",
        )
        for key in ("ReadinessStage", "OperationStage", "OperationErrno",
                    "ParkStage", "ParkErrno"):
            self.assertIn(key, self.persistence)
        self.assertIn("persist_socket_diagnostic_dictionary()", finish)

    def test_termination_quiesce_closes_admission_and_parks_under_krw_lock(self) -> None:
        quiesce = self.function_body(
            "bool kexploit_prepare_recoverable_termination(",
            "bool kexploit_quiesce_for_process_termination(void)",
        )
        # The exact current-generation anchor is proven before admission
        # closes, so a failed proof leaves the primitive untouched.
        anchor = quiesce.index("krw_persistence_verify_current_generation_anchor(")
        gate = quiesce.index(
            "atomic_store_explicit(&gKrwTerminationQuiescing, true"
        )
        lock = quiesce.index("pthread_mutex_lock(&krwLock)")
        park = quiesce.index("statePresent && krw_park_rw_socket_locked()", lock)
        verify = quiesce.index(
            "krw_verify_canonical_pair_parked_locked(&parkProof)", park
        )
        unlock = quiesce.index("pthread_mutex_unlock(&krwLock)", verify)
        self.assertLess(anchor, gate)
        self.assertLess(gate, lock)
        self.assertLess(lock, park)
        self.assertLess(park, verify)
        self.assertLess(verify, unlock)
        self.assertNotIn("early_kwrite64_checked", quiesce)
        self.assertNotIn("gKrwRestoreSnapshot.controlCksum", quiesce)
        self.assertIn("krw_park_rw_socket_locked", quiesce)
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
            "CNDKRWTerminationDisposition settings_best_effort_termination_cleanup(const char *reason)"
        )
        end = self.settings.index(
            "void settings_destroy_springboard_remote_call_sync(void)", start
        )
        cleanup = self.settings[start:end]
        timeout = cleanup.index("if (!locked)")
        quiesce = cleanup.index(
            "kexploit_quiesce_for_process_termination()", timeout
        )
        early_return = cleanup.index(
            "return settings_finish_termination_cleanup(disposition);", quiesce
        )
        self.assertLess(timeout, quiesce)
        self.assertLess(quiesce, early_return)
        self.assertNotIn(
            "Last-chance cleanup skipped because another operation is still active",
            cleanup,
        )

    def test_persistence_writes_complete_version_five_transaction_records(self) -> None:
        save = self.persistence_function_body(
            "static bool persist_save_primitive(",
            "static void persist_record_anchor_diagnostic",
        )
        self.assertIn('@"Version": @(kKRWPrimitiveSchemaVersion)', save)
        self.assertIn('@"GenerationID": generationID', save)
        self.assertIn('@"State": recordState', save)
        self.assertIn('@"HandoffSerial": @(handoffSerial)', save)
        self.assertIn('@"PreparedByPID": @(getpid())', save)
        self.assertNotIn("kKRWSuccessorGrantPoolKey", save)
        self.assertNotIn("successorGrantPool", save)
        self.assertIn('@"RestoreControlFilter"', save)
        self.assertIn('@"RestoreControlCksum"', save)
        self.assertIn('@"RestoreRWFilter"', save)
        self.assertIn('@"RestoreRWCksum"', save)
        self.assertIn('@"RestoreRWState"', save)
        self.assertIn('@"BootIdentity"', save)
        self.assertIn("sizeof(restoreSnapshot->rwState)", save)
        self.assertIn("persist_write_primitive_record", save)

        transfer = self.persistence_function_body(
            "CNDKRWPersistenceTransferResult krw_persistence_transfer_to_launchd(void)",
            "static bool persist_consume_saved_token",
        )
        prepared = transfer.index("kKRWRecordStatePrepared")
        rw_register = transfer.index(
            "bootstrap_register(bootstrap_port, rwPortName, rwPort)"
        )
        committed = transfer.index("kKRWRecordStateCommitted", rw_register)
        self.assertLess(prepared, rw_register)
        self.assertLess(rw_register, committed)
        self.assertNotIn("kKRWSuccessorGrantPoolCapacity", transfer)
        self.assertNotIn("successor-grant-pool", transfer)
        self.assertEqual(transfer.count('failureStage = "control-lookup-token"'), 1)
        self.assertEqual(transfer.count('failureStage = "rw-lookup-token"'), 1)

        recover = self.persistence_function_body(
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)",
            "\nbool krw_persistence_recover(void)",
        )
        self.assertIn('primitive[@"RestoreRWState"]', recover)
        self.assertIn("kexploit_krw_restore_snapshot_import(&restoreSnapshot)", recover)

    def test_rearm_proves_one_reusable_pair_without_rotating_tokens(self) -> None:
        rearm = self.persistence_function_body(
            "bool krw_persistence_rearm_next_process(CNDKRWRearmResult *outResult)",
            "static bool persist_consume_saved_token",
        )
        self.assertIn("persist_reusable_grant_pair_present(primitive)", rearm)
        self.assertIn("result.reusableGrantPairPresent", rearm)
        self.assertIn("krw_persistence_export_recovery_handoff", rearm)
        self.assertIn("post-reusable-grant-anchor", rearm)
        self.assertIn("reusable-grant-pair-proven-exact", rearm)
        self.assertNotIn("persist_write_primitive_record", rearm)
        self.assertNotIn("persist_issue_mach_token", rearm)
        self.assertNotIn("removeObjectAtIndex", rearm)
        self.assertNotIn('updated[@"ControlPortToken"]', rearm)
        self.assertNotIn('updated[@"RWPortToken"]', rearm)
        self.assertNotIn("remote_call", rearm.lower())

        recover = self.persistence_function_body(
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)",
            "\nbool krw_persistence_recover(void)",
        )
        migration = recover[
            recover.index("NSMutableDictionary *committed = [primitive mutableCopy]"):
            recover.index("CNDKRWRearmResult rearm = {0};")
        ]
        self.assertIn('@"Version"] = @(kKRWPrimitiveSchemaVersion)', migration)
        self.assertIn("removeObjectForKey:kKRWSuccessorGrantPoolKey", migration)
        self.assertNotIn('committed[@"ControlPortToken"] =', migration)
        self.assertNotIn('committed[@"RWPortToken"] =', migration)

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

    def test_root_file_token_is_independent_from_krw_recovery(self) -> None:
        transfer = self.persistence_function_body(
            "CNDKRWPersistenceTransferResult krw_persistence_transfer_to_launchd(void)",
            "static bool persist_consume_saved_token",
        )
        root_token = transfer.index("persist_issue_file_token")
        fileports = transfer.index("fileport_makeport")
        register = transfer.index("bootstrap_register")
        prepared_save = transfer.index("persist_save_primitive")
        committed_save = transfer.index("persist_save_primitive", prepared_save + 1)
        self.assertLess(root_token, fileports)
        self.assertLess(root_token, register)
        self.assertLess(root_token, prepared_save)
        self.assertLess(prepared_save, register)
        self.assertLess(register, committed_save)
        self.assertNotIn("persist_save_launchd_root_file_token", transfer)
        root_attempt = transfer[
            transfer.index("if (!persist_issue_file_token"):
            transfer.index('failureStage = "control-register-token"')
        ]
        self.assertNotIn("break;", root_attempt)
        self.assertIn("continuing KRW anchor without it", root_attempt)
        save_body = self.persistence_function_body(
            "static bool persist_save_primitive(",
            "static void persist_record_anchor_diagnostic",
        )
        write_body = self.persistence_function_body(
            "static bool persist_write_primitive_record(",
            "static bool persist_save_primitive(",
        )
        self.assertIn(
            'forKey:kLaunchdRootFileTokenDefaultsKey', write_body
        )
        self.assertIn("BOOL rootTokenPersisted = !updateRootToken", write_body)
        self.assertIn("previousPrimitive", write_body)
        self.assertIn("persist_write_primitive_record", save_body)
        self.assertIn("failed to durably save complete KRW recovery record", save_body)
        self.assertIn('Anchor result: %s stage=%s generation=%s "', transfer)

        has_saved = self.persistence_function_body(
            "bool krw_persistence_has_saved_recovery(void)",
            "static bool persist_is_kernel_ptr",
        )
        metadata = self.persistence_function_body(
            "static bool persist_metadata_matches_current_generation(",
            "bool krw_persistence_verify_current_generation_anchor(",
        )
        recover = self.persistence_function_body(
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)",
            "\nbool krw_persistence_recover(void)",
        )
        for body in (has_saved, metadata, recover):
            self.assertNotIn("persist_saved_launchd_root_file_token", body)
            self.assertNotIn("root-file-token-missing", body)

    def test_recovery_consumes_each_saved_lookup_token_at_most_once(self) -> None:
        start = self.persistence.rindex("static bool persist_consume_saved_token(")
        end = self.persistence.index("static void persist_close_recovered_fds", start)
        consume = self.persistence[start:end]
        self.assertIn("if (*retainedHandle >= 0)", consume)
        self.assertIn("[retainedToken isEqualToString:token]", consume)
        self.assertIn("*retainedHandle = handle", consume)
        self.assertIn("gKRWControlLookupToken = [token copy]", consume)
        self.assertIn("gKRWRWLookupToken = [token copy]", consume)

        recover = self.persistence_function_body(
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)",
            "\nbool krw_persistence_recover(void)",
        )
        self.assertEqual(recover.count('persist_consume_saved_token(primitive, @"ControlPortToken"'), 1)
        self.assertEqual(recover.count('persist_consume_saved_token(primitive, @"RWPortToken"'), 1)
        self.assertNotIn("krw_persistence_verify_current_generation_anchor", recover)

    def test_recovery_validates_the_already_recovered_fd_identities(self) -> None:
        identity = self.persistence_function_body(
            "static bool persist_recovered_fds_match_saved_socket_identity(",
            "static const char *persist_saved_port_name",
        )
        self.assertIn("persist_fileglob_for_fd(selfProc, controlSocket)", identity)
        self.assertIn("persist_fileglob_for_fd(selfProc, rwSocket)", identity)
        self.assertIn("controlGlob + off_fileglob_fg_data", identity)
        self.assertIn("savedControlPcb + off_inpcb_inp_socket", identity)
        self.assertIn("controlFDData == savedControlSocket", identity)
        self.assertIn("rwFDData == savedRWSocket", identity)

    def test_launchd_registration_pins_rw_before_forged_control(self) -> None:
        transfer = self.persistence_function_body(
            "CNDKRWPersistenceTransferResult krw_persistence_transfer_to_launchd(void)",
            "static bool persist_consume_saved_token",
        )
        rw_register = transfer.index(
            "bootstrap_register(bootstrap_port, rwPortName, rwPort)"
        )
        control_register = transfer.index(
            "bootstrap_register(bootstrap_port, controlPortName, controlPort)"
        )
        self.assertLess(rw_register, control_register)

    def test_launchd_persistence_requires_exact_identity_bootstrap(self) -> None:
        transfer = self.persistence_function_body(
            "CNDKRWPersistenceTransferResult krw_persistence_transfer_to_launchd(void)",
            "static bool persist_consume_saved_token",
        )
        self.assertIn(
            "init_remote_call_identity_bootstrap_original_thread_only", transfer
        )
        self.assertIn("launchdSnapshot.identityThreadRightExact", transfer)
        self.assertIn("launchdSnapshot.identityTaskRightExact", transfer)

    def test_persistence_is_saved_before_launchd_teardown(self) -> None:
        transfer = self.persistence_function_body(
            "CNDKRWPersistenceTransferResult krw_persistence_transfer_to_launchd(void)",
            "static bool persist_consume_saved_token",
        )
        prepared = transfer.index("preparedSaved = persist_save_primitive")
        committed = transfer.index("committedSaved = persist_save_primitive")
        teardown = transfer.index("destroy_remote_call()")
        verify = transfer.index(
            "krw_persistence_verify_current_generation_anchor(&verification)",
            teardown,
        )
        self.assertLess(prepared, committed)
        self.assertLess(committed, teardown)
        self.assertLess(teardown, verify)
        self.assertIn("int teardownResult = destroy_remote_call();", transfer)
        self.assertIn("remote_call_current_success()", transfer)

    def test_committed_generation_has_a_read_verified_container_backup(self) -> None:
        export = self.persistence_function_body(
            "bool krw_persistence_export_recovery_handoff(NSString **stage)",
            "bool krw_persistence_handoff_backup_exact(NSString **stage)",
        )
        self.assertIn("persist_current_recovery_handoff()", export)
        self.assertIn("NSPropertyListBinaryFormat_v1_0", export)
        self.assertIn("options:NSDataWritingAtomic", export)
        self.assertIn("persist_read_recovery_handoff(&readError)", export)
        self.assertIn("isEqualToDictionary:handoff", export)

        transfer = self.persistence_function_body(
            "CNDKRWPersistenceTransferResult krw_persistence_transfer_to_launchd(void)",
            "static bool persist_consume_saved_token",
        )
        verify = transfer.index(
            "krw_persistence_verify_current_generation_anchor(&verification)"
        )
        backup = transfer.index(
            "krw_persistence_export_recovery_handoff(&backupStage)", verify
        )
        result = transfer.index("CNDKRWPersistenceTransferResult result", backup)
        self.assertLess(verify, backup)
        self.assertLess(backup, result)

        rearm = self.persistence_function_body(
            "bool krw_persistence_rearm_next_process(CNDKRWRearmResult *outResult)",
            "static bool persist_consume_saved_token",
        )
        backup = rearm.index(
            "krw_persistence_export_recovery_handoff(&backupStage)"
        )
        post = rearm.index("post-reusable-grant-anchor", backup)
        self.assertLess(backup, post)
        self.assertNotIn("persist_write_primitive_record", rearm)
        self.assertNotIn(
            "init_remote_call_identity_bootstrap_original_thread_only", rearm
        )
        self.assertNotIn("destroy_remote_call", rearm)

    def test_missing_defaults_restore_only_from_exact_same_boot_backup(self) -> None:
        recover = self.persistence_function_body(
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)",
            "\nbool krw_persistence_recover(void)",
        )
        no_record = recover.index('"no-record"')
        backup_present = recover.index("backupPresent")
        import_backup = recover.index(
            "krw_persistence_import_recovery_handoff(handoff, &importStage)"
        )
        cross_boot = recover.index('"handoff-backup-cross-boot"')
        token = recover.index("persist_consume_saved_token", import_backup)
        self.assertLess(backup_present, no_record)
        self.assertLess(no_record, import_backup)
        self.assertLess(import_backup, token)
        self.assertIn("CNDKRWPersistenceRecoveryRetryableFailure", recover)
        self.assertIn("handoff-backup-read", recover)
        self.assertIn("handoff-backup-import", recover)
        self.assertGreater(cross_boot, import_backup)

        imported = self.persistence_function_body(
            "bool krw_persistence_import_recovery_handoff(",
            "static bool persist_is_kernel_ptr",
        )
        self.assertIn("isSubsetOfSet:allowedTopKeys", imported)
        self.assertIn("persist_primitive_is_committed", self.persistence)
        self.assertIn("persist_write_primitive_record(", imported)

    def test_primary_recovery_is_status_driven_and_blocks_retryable_stacking(self) -> None:
        recover = self.persistence_function_body(
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)",
            "\nbool krw_persistence_recover(void)",
        )
        self.assertIn("CNDKRWPersistenceRecoveryRetryableFailure", recover)
        self.assertIn("CNDKRWPersistenceRecoveryStaleRecord", recover)
        validation = recover.index(
            "if (!recoveredPairActivated || !kexploit_krw_ready())"
        )
        later_validation = recover.index("uint64_t launchdProc", validation)
        prepared = recover[:validation]
        self.assertIn("prepared-generation-holder-unknown-preserved", prepared)
        self.assertNotIn("persist_forget_saved_primitive", recover)
        dead_token = prepared[prepared.index("if (controlTokenDead || rwTokenDead)"):]
        dead_token = dead_token[:dead_token.index("mach_port_t controlPort")]
        self.assertIn("saved reusable sandbox token missing", dead_token)
        self.assertNotIn("gKRWLastRecoveryTokenBurn = true;", dead_token)
        self.assertIn("CNDKRWPersistenceRecoveryRetryableFailure", dead_token)
        self.assertIn('"sandbox-token-missing-preserved"', dead_token)
        # Missing or rejected bearers preserve the record and never prove release.
        retryable_token = dead_token[dead_token.index("CNDKRWPersistenceRecoveryRetryableFailure"):]
        self.assertIn('"sandbox-token-consume-retryable"', retryable_token)
        self.assertNotIn("persist_forget_saved_primitive", retryable_token)
        dead_pair = recover[validation:later_validation]
        self.assertEqual(dead_pair.count("persist_forget_saved_primitive"), 0)
        self.assertIn("kexploit_control_socket_park_probe()", dead_pair)
        self.assertIn("kexploit_krw_socket_diagnostic()", dead_pair)
        self.assertNotIn("CNDKRWPersistenceRecoveryStaleRecord", dead_pair)
        self.assertIn('"recovered-pair-validation-indeterminate"', dead_pair)
        self.assertNotIn("CNDKRWPersistenceRecoveryUnusablePairReleased", dead_pair)
        self.assertNotIn("persist_forget_saved_primitive", recover[later_validation:])
        exploit_entry = self.exploit[
            self.exploit.index("int kexploit_opa334(void)"):
        ]
        self.assertIn("krw_persistence_recover_with_status()", exploit_entry)
        self.assertIn("recovery_retryable_blocked", exploit_entry)
        self.assertIn("return EAGAIN;", exploit_entry)

    def test_same_boot_unknown_services_never_authorize_reacquisition(self) -> None:
        recover = self.persistence_function_body(
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)",
            "\nbool krw_persistence_recover(void)",
        )
        committed_unknown = recover.index(
            "if (controlKR == kCNDBootstrapUnknownService &&\n"
            "            rwKR == kCNDBootstrapUnknownService)"
        )
        unknown = recover[committed_unknown:]
        unknown = unknown[:unknown.index("launchd recovery lookup failed ambiguously")]
        self.assertIn("launchd-services-unknown-same-boot", unknown)
        self.assertIn("CNDKRWPersistenceRecoveryRetryableFailure", unknown)
        self.assertNotIn("CNDKRWPersistenceRecoveryStaleRecord", unknown)
        self.assertIn("acquisition is blocked", unknown)

    def test_time_boot_identity_detects_reboot_with_fractional_tolerance(self) -> None:
        relationship = self.persistence_function_body(
            "static CNDKRWBootIdentityRelationship\npersist_primitive_boot_identity_relationship(NSDictionary *primitive)\n{",
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
        self.assertIn("persist_finish_recovery(CNDKRWPersistenceRecoveryRetryableFailure", uncertain_branch)
        self.assertIn("refusing socket", uncertain_branch)
        self.assertIn("reconstruction or fresh acquisition", uncertain_branch)

        saved = self.persistence_function_body(
            "bool krw_persistence_has_saved_recovery(void)",
            "static bool persist_is_kernel_ptr",
        )
        self.assertIn("persist_recovery_disabled_for_current_build()", saved)
        self.assertIn("persist_primitive_boot_identity_relationship", saved)
        self.assertIn("persist_primitive_has_complete_restore_state", saved)

    def test_transfer_failure_verifies_local_socket_park(self) -> None:
        entry = self.function_body("int kexploit_opa334(void)", "return 0;\n}")
        failure = entry[
            entry.index(
                "if (persistenceResult != CNDKRWPersistenceTransferCommittedExact)"
            ):
        ]
        self.assertIn("cnd_park_committed_primitive()", failure)
        self.assertIn("CNDKExploitOutcomeUnsafeUnverified", failure)
        self.assertIn("persistence_failed_unsafe", failure)
        self.assertIn("persistence_failed_locally_parked", failure)

    def test_non_exact_transfer_keeps_the_won_primitive_admissible(self) -> None:
        """A non-exact launchd handoff must not be reported as a failed acquisition.

        Next-process arming is a durable-continuity property. Treating it as a
        usability precondition discarded races that had already succeeded: the
        caller treats a non-zero result as failure without ever validating the
        primitive it holds.
        """
        entry = self.function_body("int kexploit_opa334(void)", "return 0;\n}")
        failure = entry[
            entry.index(
                "if (persistenceResult != CNDKRWPersistenceTransferCommittedExact)"
            ):
        ]
        # The enum is used for graduated reporting, not collapsed into refusal.
        for outcome in (
            "CNDKRWPersistenceTransferCommittedUnverified",
            "CNDKRWPersistenceTransferPreparedOnly",
            "CNDKRWPersistenceTransferPartialHolder",
        ):
            self.assertIn(outcome, failure)
        self.assertIn("persistence_unverified_committed", failure)
        self.assertNotIn("return EAGAIN;", failure)
        self.assertIn("return 0;", failure)
        # The refusal boundary is the local park, not the durable enum: the only
        # non-admitting exit left is the one where the park could not be
        # verified, and it must report unsafe rather than clean.
        refused = failure[:failure.index("switch (persistenceResult)")]
        self.assertIn("!locallyParked", refused)
        self.assertIn("CNDKExploitOutcomeUnsafeUnverified", refused)
        self.assertIn("return -1;", refused)

        # And the usability predicate no longer requires next-process arming.
        usable = self.settings_function_body(
            "static BOOL settings_krw_generation_usable(void)",
            "static BOOL settings_observe_krw_generation_usable(void)",
        )
        self.assertIn("kexploit_krw_ready()", usable)
        self.assertNotIn("krw_persistence_next_process_armed()", usable)

    def test_recovered_live_pair_survives_reusable_grant_proof_failure(self) -> None:
        """Durable handoff proof cannot revoke a validated local primitive."""
        recover = self.persistence_function_body(
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)",
            "\nbool krw_persistence_recover(void)",
        )
        rearm = recover[recover.index("CNDKRWRearmResult rearm = {0};"):]
        self.assertNotIn("kKRWRecoveryRearmRetryLimit", rearm)
        self.assertEqual(rearm.count("krw_persistence_rearm_next_process(&rearm)"), 1)
        self.assertIn("krw_persistence_rearm_next_process(&rearm)", rearm)
        self.assertNotIn("init_remote_call_identity_bootstrap_original_thread_only", rearm)
        self.assertIn("gKRWPersistenceRecovered = true;", rearm)
        self.assertIn('"recovered-local-unarmed:%s"', rearm)
        self.assertIn(
            "CNDKRWPersistenceRecoveryRecovered, recoveryStage", rearm
        )
        local_unarmed = rearm[rearm.index("if (!rearmed)"):]
        local_unarmed = local_unarmed[:local_unarmed.index(
            'return persist_finish_recovery(CNDKRWPersistenceRecoveryRecovered, "recovered")'
        )]
        self.assertNotIn(
            "CNDKRWPersistenceRecoveryRetryableFailure", local_unarmed
        )

        exploit = self.function_body("int kexploit_opa334(void)", "return 0;\n}")
        recovered = exploit[
            exploit.index("if (recoveryResult == CNDKRWPersistenceRecoveryRecovered)"):
            exploit.index(
                "if (recoveryResult == CNDKRWPersistenceRecoveryRetryableFailure ||"
            )
        ]
        self.assertIn("krw_persistence_next_process_armed()", recovered)
        self.assertIn("recovered_local_unarmed", recovered)
        self.assertIn("return 0;", recovered)

        respring = self.settings_function_body(
            "static BOOL settings_prepare_for_respring_sync(void)",
            "static CNDKRWTerminationDisposition",
        )
        self.assertIn("krw_persistence_next_process_armed()", respring)
        cleanup = self.function_body(
            "bool kexploit_terminal_cleanup_with_disposition(",
            "bool kexploit_terminal_cleanup(void)",
        )
        self.assertIn("recoverable = anchorExact &&", cleanup)
        self.assertIn("krw_persistence_next_process_armed()", cleanup)

    def test_retry_ladder_defers_to_the_durable_holder(self) -> None:
        """A launchd-held pair retires the retry ladder, not just the enum.

        The outcome enum only describes what this pass left behind locally; it
        cannot see a socket pair the pass handed to launchd. Racing the socket
        zones again on top of a held pair is the retry that turns a clean
        failure into a corrupted session.
        """
        ensure = self.settings_function_body(
            "static BOOL settings_ensure_kexploit(void)",
            "static void settings_run_lsreg_baseline_action(void)",
        )
        retry = ensure[ensure.index("BOOL safelyRetryable"):]
        self.assertIn("krw_persistence_launchd_holds_krw()", retry)
        self.assertIn("launchdHoldsKrw", retry)
        self.assertIn("!safelyRetryable || launchdHoldsKrw ||", retry)

    def test_a18_short_settle_requires_a_churned_allocator(self) -> None:
        """The short retry settle must not apply to a pass that never wired.

        A pass that aborted before starting a wired batch leaves the allocator
        exactly as the long settle found it; shortening the next settle there
        reproduces the three-second regression that faulted in
        physical_oob_read_mo.
        """
        self.assertIn("static bool gA18AllocatorChurned", self.exploit)
        self.assertIn("gA18AllocatorChurned = true;", self.exploit)
        settle = self.exploit[
            self.exploit.index("bool allocatorChurned = gA18AllocatorChurned;") :
        ]
        settle = settle[: settle.index("sleep(settleSeconds);")]
        self.assertIn("gA18AllocatorChurned = false;", settle)
        self.assertIn(
            "unsigned settleSeconds = (a18SettleDone && allocatorChurned) ? 1 : 8;",
            settle,
        )
        # The churn flag is set where a wired batch actually starts.
        wired = self.exploit[
            self.exploit.index("gExploitAttemptCounters.wiredBatchesStarted++;") :
        ]
        self.assertTrue(wired.startswith(
            "gExploitAttemptCounters.wiredBatchesStarted++;\n    gA18AllocatorChurned = true;"
        ))

    def test_oob_miss_stop_reports_the_failing_span(self) -> None:
        """The consecutive-miss stop is a bound on aperture exposure.

        It must not be raised without knowing whether the unproductive run was
        confined to one region (a broken coordinator or aperture window) or
        spread across the walk (an unproductive search), so the stop reports
        the first and last failing offsets and both kernel returns.
        """
        self.assertIn("mach_vm_offset_t firstMissOffset = 0;", self.exploit)
        self.assertIn("kern_return_t firstMissKr = KERN_SUCCESS;", self.exploit)
        stop = self.exploit[
            self.exploit.index(
                "PE_V2_MAX_CONSECUTIVE_OOB_READ_MISSES) {",
            ) :
        ]
        stop = stop[: stop.index("raceQualityStopped = true;")]
        for token in ("firstMissOffset", "firstMissKr", "span="):
            self.assertIn(token, stop)

    def test_no_primitive_cleanup_is_not_reported_unsafe(self) -> None:
        # A process that never held a primitive must not announce
        # "unsafe-unverified" while returning the no-primitive disposition.
        # That contradiction is what made an ordinary close look like a lost
        # parked generation.
        cleanup = self.function_body(
            "bool kexploit_terminal_cleanup_with_disposition(",
            "bool kexploit_terminal_cleanup(void)",
        )
        no_snapshot = cleanup[:cleanup.index("if (!is_kaddr_valid(controlSocketPcb)")]
        self.assertIn("hadPrimitive", no_snapshot)
        self.assertIn(
            "gKExploitLastOutcome = hadPrimitive\n"
            "            ? CNDKExploitOutcomeUnsafeUnverified\n"
            "            : CNDKExploitOutcomeCleanFailure;",
            no_snapshot,
        )
        self.assertNotIn(
            "gKExploitLastOutcome = CNDKExploitOutcomeUnsafeUnverified;",
            no_snapshot,
        )

    def test_same_boot_anchor_diagnostic_blocks_reacquisition(self) -> None:
        # The anchor diagnostic records the boot identity so a later launch
        # whose saved record is gone can prove a launchd-held generation still
        # exists on this exact boot and refuse a physical re-acquisition.
        self.assertIn(
            "bool krw_persistence_same_boot_anchor_proven(void);",
            self.persistence_header,
        )
        proven = self.persistence_function_body(
            "bool krw_persistence_same_boot_anchor_proven(void)",
            "bool krw_persistence_import_recovery_handoff(",
        )
        self.assertIn("kKRWAnchorDiagnosticDefaultsKey", proven)
        self.assertIn('diagnostic[@"Verified"]', proven)
        self.assertIn('diagnostic[@"Stage"]', proven)
        self.assertIn("persist_primitive_boot_identity_relationship", proven)
        self.assertIn(
            "CNDKRWBootIdentityRelationshipMatches",
            proven,
        )
        # The anchor diagnostic must persist the boot identity, or "same boot"
        # cannot be proven across processes.
        diagnostic = self.persistence_function_body(
            "static void persist_record_anchor_diagnostic(",
            "static uint64_t persist_fileglob_for_fd(",
        )
        self.assertIn('@"BootIdentity"', diagnostic)
        # A same-boot socket rejection preserves the independent anchor witness.
        # Historical retirement markers are no longer authority to reopen the
        # gate; only a definitive boot change may authorize another acquisition.
        self.assertNotIn("persist_forget_saved_primitive", self.persistence)
        self.assertNotIn(
            "removeObjectForKey:kKRWAnchorDiagnosticDefaultsKey",
            self.persistence,
            "the anchor witness must never be deleted",
        )
        self.assertNotIn("persist_release_unusable_same_boot_record", self.persistence)
        self.assertNotIn(
            'if ([diagnostic[@"RetiredByRelease"] boolValue]) return false;', proven
        )
        # The fresh-acquisition fall-through must consult the gate.
        entry = self.function_body("int kexploit_opa334(void)", "return 0;\n}")
        gate = entry[
            entry.index("if (krw_persistence_same_boot_anchor_proven())"):
            entry.index("if (!init_globals())")
        ]
        self.assertIn("same_boot_anchor_blocks_reacquisition", gate)
        self.assertIn("return EAGAIN;", gate)

    def test_failed_recovery_records_a_control_readback(self) -> None:
        """A rejected park must not be the only evidence a failure leaves.

        Rejection alone cannot separate "this descriptor is not the forged
        socket" from "the descriptor is fine but the forge is gone", and the
        identity check that could tell them apart needs the very primitive that
        is broken. A read of the same option the primitive uses is the one
        primitive-free discriminator, and it must run while the recovered
        descriptors are still open.
        """
        probe = self.function_body(
            "bool kexploit_control_socket_readback(CNDKRWSocketDiagnostic *out)",
            "static bool cnd_park_committed_primitive(void)",
        )
        self.assertIn("getsockopt(", probe)
        self.assertNotIn("setsockopt(", probe,
                         "the readback must not change socket state")
        self.assertIn("readbackErrno", probe)
        self.assertIn("readbackLength", probe)

        entry = self.persistence_function_body(
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)",
            "bool krw_persistence_recover(void)",
        )
        readback = entry.index(
            "kexploit_control_socket_readback(&controlReadback)")
        self.assertLess(
            readback,
            entry.index("persist_clear_recovered_kernel_state()", readback),
            "the readback needs the recovered descriptors still open",
        )
        self.assertIn("gKRWLastRecoverySocketDiagnostic.readbackObserved", entry)
        self.assertIn("control-readback=%d/%d length=%u", entry)

    def test_socket_rejection_never_releases_same_boot_admission(self) -> None:
        """No socket errno proves that launchd released retained fileports."""
        entry = self.persistence_function_body(
            "CNDKRWPersistenceRecoveryResult krw_persistence_recover_with_status(void)",
            "bool krw_persistence_recover(void)",
        )
        self.assertIn("if (parkProbe == CNDKRWParkProbeAlive)", entry)
        self.assertIn('"recovered-pair-validation-indeterminate"', entry)
        self.assertIn("CNDKRWPersistenceRecoveryRetryableFailure", entry)
        self.assertNotIn("persist_release_unusable_same_boot_record", entry)
        self.assertNotIn("CNDKRWPersistenceRecoveryUnusablePairReleased", entry)

        probe = self.function_body(
            "CNDKRWParkProbeResult kexploit_control_socket_park_probe(void)",
            "bool kexploit_control_socket_parkable(void)",
        )
        self.assertNotIn("CNDKRWParkProbeDead", probe)
        self.assertNotIn("definitiveFailure", probe)
        self.assertIn("return CNDKRWParkProbeIndeterminate;", probe)


if __name__ == "__main__":
    unittest.main()
