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

    def test_persistence_requires_a_complete_version_two_snapshot(self) -> None:
        self.assertIn('@"Version": @2', self.persistence)
        self.assertIn('@"RestoreRWState"', self.persistence)
        self.assertIn("restoreSnapshot.rwStateComplete = true", self.persistence)
        self.assertIn("persist_primitive_has_complete_restore_state", self.persistence)
        self.assertIn("unsupported or incomplete restore snapshot", self.persistence)
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
