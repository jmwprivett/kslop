
## Advice — what to do next, in order

1. **Run the built physical canaries first** (`CNDPhysicalPACIdentityCanary`, then `CrossTaskCanary`, then the ATTACHEXC RX probe) on the next healthy boot on iPinky Max. One device session answers: does stock-boot identity delivery yield a convertible right? That is the fork in the road for the whole converter/PAC plan.
2. **Run the arm64e signing-gadget census with REA** on the exact physical 23A341 kernelcache (already UUID-bound tooling): `blraa`/`braa` call sites, signing helpers, `IOExternalMethod` tables, kext dispatch arrays. It feeds two quests at once (PAC primitive + data-only kcall target list). Timebox it; the tooling exists.
3. **Survey writable kernel DATA for called function-pointer slots** on 23A341. Combine the census output with `kwrite32` and the `.34` lesson (maxProt is not truth; permission tickets are). One verified, legitimately-called, writable slot *is* the physical kcall port.
4. **Test `pmap_sign_user_ptr` under kernel context on the VM** (bounded, synthetic, same discipline as the runtime probes). If it signs kernel-keyed data pointers, the forged `ip_kobject` bridge comes back to life and Rank 3 gets cheap.
5. **Wire TaskRop to `EXCEPTION_STATE_IDENTITY`** behind a physical-canary gate, keeping `remote_pac` as fallback — already the documented plan; execute after (1).
6. **Implement the KRW lease/broker** (file lock held across read-modify-write sessions). Pure engineering, unblocks portability and the SpringBoard-resident supervisor, removes a documented corruption hazard.
7. **Do not spend more time on**: aperture text writes (dead), recover-table PC (dead), EL1-mode thread_set_state (dead), unentitled trust-cache loads (stopped at the genuine boundary), and any forged `ip_kobject` route until (4) says kernel-keyed signing is reachable.
