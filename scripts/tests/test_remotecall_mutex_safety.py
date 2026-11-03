"""Structural checks for the RemoteCall dummy-mutex ownership gate."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError(f"unterminated function: {signature}")


class RemoteCallMutexSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (ROOT / "Cyanide/TaskRop/RemoteCall.m").read_text()

    def test_release_only_rewrites_our_forged_owner(self) -> None:
        release = function_body(
            self.source, "static void release_forged_dummy_mutex"
        )
        read = release.index("thread_get_mutex(g_RC_dummyThreadAddr)")
        gate = release.index(
            "(mtx & CND_LCK_MTX_CTID_MASK) == g_RC_selfThreadCtid"
        )
        write = release.index(
            "thread_set_mutex(g_RC_dummyThreadAddr, "
            "CND_LCK_MTX_NEEDS_WAKEUP)"
        )
        self.assertLess(read, gate)
        self.assertLess(gate, write)
        self.assertIn("} else {", release[write:])

    def test_forge_requires_a_free_dummy_mutex(self) -> None:
        bootstrap = function_body(
            self.source, "bool set_exception_port_on_thread"
        )
        read = bootstrap.index(
            "uint32_t dummyMutexBefore = "
            "thread_get_mutex(g_RC_dummyThreadAddr)"
        )
        free_gate = bootstrap.index(
            "(dummyMutexBefore & CND_LCK_MTX_CTID_MASK) != 0"
        )
        forge = bootstrap.index(
            "thread_set_mutex(g_RC_dummyThreadAddr, g_RC_selfThreadCtid)"
        )
        resume = bootstrap.index("thread_resume_wrapper(machThread)")
        nonfree = bootstrap[free_gate:forge]
        self.assertLess(read, free_gate)
        self.assertIn(
            'release_forged_dummy_mutex("pre-forge mutex not free")',
            nonfree,
        )
        self.assertIn("pthread_cancel(pthread)", nonfree)
        self.assertIn("return false;", nonfree)
        self.assertLess(free_gate, forge)
        self.assertLess(forge, resume)

    def test_every_post_forge_exit_releases_through_owner_gate(self) -> None:
        bootstrap = function_body(
            self.source, "bool set_exception_port_on_thread"
        )
        resume = bootstrap.index("thread_resume_wrapper(machThread)")
        resume_failure = bootstrap.index(
            'release_forged_dummy_mutex("helper resume failed")', resume
        )
        cancel = bootstrap.index("pthread_cancel(pthread)", resume_failure)
        normal_release = bootstrap.index(
            'release_forged_dummy_mutex("helper finished")', cancel
        )
        wake = bootstrap.index(
            "thread_set_exception_ports(g_RC_dummyThreadMach", normal_release
        )
        self.assertLess(resume_failure, cancel)
        self.assertLess(normal_release, wake)
        self.assertNotIn(
            "thread_set_mutex(g_RC_dummyThreadAddr, 0x40000000)",
            bootstrap,
        )


if __name__ == "__main__":
    unittest.main()
