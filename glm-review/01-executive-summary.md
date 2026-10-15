## Executive summary

Two quests, one shared wall.

**Quest 1 — find a PAC bypass (arm64e, iPhone17,2, 23A341).** You have systematically eliminated almost every "cheap" route: text-frame aperture writes (dead, deterministic permission fault), forged `ipc_port::ip_kobject` task ports (dead, destination data PAC), `thread->recover` PC control (dead, bounds-checked table), `thread_set_state`-driven EL1 PC (dead, EL0 sanitization). You have two live assets: (a) confirmed writable aperture **data** pages (`.33 __DATA_CONST` and, remarkably, `.34 dyldreadonly r--`), which produced a working semantic ObjC dispatch redirect; and (b) a fully REA-verified kernel PAC signing surface (`ml_sign_thread_state`, pmap/SPTM selector `0x10`/`0x11`, `thread_state64_to_saved_state`, public `thread_convert_thread_state` converters) proven on the VM with a physical KRW-only `remote_pac` fallback already in the tree. The physical identity-delivery canary (`EXCEPTION_STATE_IDENTITY`) is **built but has no recorded physical run** — that is the biggest cheap unexecuted experiment on the board.

**Quest 2 — port the KRW into a kcall.** On the VM this is done and honestly fenced off (syscall-439 provider, `cnd_lab_kernel_call`, capability `0xf` smoke tests). On the physical arm64e device the port is **not started as a port**: XPF's `kcall_return` gadget set is explicitly disabled on arm64e, every attempt to route through thread-state signing sanitized back to EL0, and the only concrete physical kcall candidate (`cs_allow_invalid` at unslid `0xfffffff0086e6b68`) is specified, prologue-verified, and **never invoked** because it is waiting on a PAC-correct kernel control-flow primitive — i.e., it is blocked on Quest 1. The two quests are the same problem seen from two sides.

Grade: A on evidence discipline and route-closure; B on the PAC surface mapping (best in class, actually); D on physical execution of the last-mile experiments — several decisive physical canaries exist as code and Settings rows but have zero recorded results.

---
