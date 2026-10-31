# kcall1 phone route derivation (iPhone17,2, iOS 26.0 23A341)

**Level: implemented.** Static derivation of the seven kcall1 route
roles against the pinned phone kernelcache (UUID
76BB58BF-911D-07E4-D681-DCE7F2DDA3CE; `phone-kernelcache-header.txt:3`
SHA-256). Nothing ran on the phone; nothing here is VM-proved or
physical-proved. The VM pins (`scripts/lab/cnd_iouserethernet_krw_trigger.m:97-115`)
remain VM-proved only for the vPhone 23A341 fileset.

## Method

- `scripts/ghidra/CndKcall1VMSignatures.java` dumped the VM statics
  (`vm-signatures.txt`, `vm-kext-signatures.txt`; `stock-fingerprint.txt`
  is the 20-line normalized stock-callback body).
- `scripts/ghidra/CndKcall1PhoneKernelFind.java` matches the stock
  callback body (exact; bti-prefixed exact; mnemonic fallback) and walks
  every maximal run of 12-byte `bti; X; ret` outline elements, selecting
  by value sequence (`8,1,2,4,8,4,8`; `ldr:,ldr:0x4,ldr:0x8,str:0x8`).
  Self-check on the research kernel: `selfcheck-research.txt` rediscovers
  all three VM pins (lines 23, 49, 55, 63). Phone output:
  `phone-kernel-find.txt`.
- `scripts/ghidra/CndKcall1PhoneKextFind.java` matches the 123-instruction
  `init_ifnet_params` body (exact, then mnemonic-only), locates the
  `mov x17,#0xe4fe; pacia; str [x19,#0x48]` signer step and the `__got`
  slot READ by the preceding `ldr x16`, and matches the 28-byte
  dispatcher exactly. Self-check on the VM kext: `selfcheck-kext.txt`
  rediscovers all four VM pins (lines 4, 134, 150, 160 area). Phone
  output: `phone-kext-find.txt`.
- Ghidra 12.1.4 headless, `-noanalysis`, on the pre-analyzed projects
  `physical-kernel-23A341` and `ionetworking-physical-23A341`.

## Phone route (all seven resolved)

Every address below is also carried by the producer's phone block
(`cnd_iouserethernet_krw_trigger.m:2949-3006`, table at `:3026-3036`); the
witness column is the record file that derived it.

| role | VM pin | phone | witness |
|---|---|---|---|
| checkmulti_got_donor | fffffe000799f588 | fffffff0080b4020 | `phone-kext-find.txt:151-156` |
| stock_callback | fffffe0007d293fc | fffffff00849044c | `phone-kernel-find.txt:23-52,136` + GOT fixup |
| init_ifnet_params | fffffe0008f87a38 | fffffff00a6da548 | `phone-kext-find.txt:4-23,158-159` |
| stock_signer | fffffe0008f87bf0 | fffffff00a6da700 | `phone-kext-find.txt:150` |
| enoexec_return_stub | fffffe00082f6a38 | fffffff008a4b5d8 | `phone-kernel-find.txt:62-69` |
| load_w0_from_x0_stub | fffffe00082f6590 | fffffff008a4b130 | `phone-kernel-find.txt:54-61,70` |
| ifnet_x0_dispatcher | fffffe0008f94a8c | fffffff00a6e759c | `phone-kext-find.txt:160-172` |

## Phone allproc (resolved 2026-10-16; `CNDStaticPhoneAllProc`)

| static | VM pin (`.m:26-27`) | phone | witness |
|---|---|---|---|
| allproc | fffffe0009813020 | fffffff00b2faa18 | `phone-allproc-find.txt:125-128,213-217,233-253` |

- `scripts/ghidra/CndKcall1ProcIterateScan.java` scans every function
  for the `proc_iterate` shape without using names or addresses: a
  64-bit `adrp+ldr` list-head load guarded by `tbz/tbnz wN,#0`
  (`PROC_ALLPROCLIST`), another guarded by bit 1 (`PROC_ZOMBPROCLIST`),
  the two statics adjacent (`zombproc == allproc + 8`). Raw AArch64
  decoding; no Ghidra reference analysis is relied on for the selection.
- Self-check on the research kernel: exactly one function of 20,771
  matches (`fffffe0007fc4ef0`, which carries no symbol there) and its
  bit-0 head is the vPhone pin `0xfffffe0009813020`
  (`phone-allproc-find.txt:10-13` `SELF-CHECK ... match true`; detail
  `:89-94`).
- Phone: exactly one function of 21,490 matches, `fffffff008726f6c`,
  which the pinned symbol map names `_proc_iterate` (`:125-128`); its
  bit-0 head is `fffffff00b2faa18`, bit-1 head `fffffff00b2faa20`
  (`:213-217`).
- Second witness: `scripts/ghidra/CndKcall1AllProcFind.java` lists every
  program-wide reference to the candidate: 15 references from 8
  functions on both images (`:110-118` VM, `:233-241` phone), and the
  phone's referencing functions are the canonical allproc users by name:
  `_pinsertchild` (the `LIST_INSERT_HEAD` writer), `_proc_shutdown`,
  `_bsd_init`, `getpriority` (`:246-253`). The static itself has no
  symbol in the map (`:254`), which is why a name lookup could not
  resolve it.
- The producer now pins `CNDStaticPhoneAllProc = 0xfffffff00b2faa18`
  (`cnd_iouserethernet_krw_trigger.m:2957-2958`), so the phone layout
  has no `CNDUnresolvedStatic` element left.

## Findings worth knowing

- The phone RELEASE_ARM64_T8140 kernel prefixes `ether_check_multi`
  with a `bti c` landing pad (size 84 vs 80); the body after it is
  identical. The research kernel has no such pad, so a plain exact match
  reports zero on the phone (`phone-kernel-find.txt:50-52`).
- The phone kernelcache is a fileset, like the VM's: container `__TEXT`
  at fffffff007004000, `com.apple.kernel` entry at fffffff00700c000
  (`phone-kernelcache-header.txt:6,10`). The `__got` chained-fixup target
  offset rebases on the container base on both images (VM:
  0xfffffe0007004000 + 0xd253fc = fffffe0007d293fc).
- `init_ifnet_params` differs from the VM only in adrp pages and
  page-offset immediates (18 DIFF lines, `phone-kext-find.txt:5-23`);
  all PAC discriminators and stores match.
- Both outline stubs sit in runs with the identical element structure
  as the VM (6-element load run, 13-element mov run), each unique in the
  whole kernel.
- The route's `load_w0_from_x0_stub` had a second claimant in the tree:
  `Cyanide/CNDPhysicalIOUserEthernetSignerProbe.m:38-39` declares
  `0xfffffff00826a470` for the same role. Settled against the image -
  it is a different stub (aligned by kind and ordinal with the VM's
  non-BTI `fffffe0007b19544`), selected by shape before the
  run-sequence method existed, and it is unused (never referenced in
  that probe). The phone pin stays `fffffff008a4b130`. Evidence:
  `load-stub-reconciliation.txt`, `phone-load-x0-return.json`,
  `vm-load-x0-return.json`.

## Load-stub reconciliation (settled 2026-10-16)

`load-stub-reconciliation.txt` re-derives the `load_w0_from_x0_stub` pin
against both images with `CndDecompileAddresses.java` and
`CndLoadX0ReturnFunctions.java`, and rejects the second claimant.
Decisive points: the phone cluster at `fffffff008a4b118` is the VM pin's
6-element run element for element, with the same boundaries; the phone's
4-element value sequence match is unique kernel-wide
(`phone-kernel-find.txt:54-60,70`); the load-run-to-ENOEXEC-run distance
is `0x4a8` on both images; and the shape-valid candidate enumeration
(`[bti c;] {ldrb|ldrh|ldr w0|ldr x0} [x0]; ret`) returns 13 entries on
each image with the same kinds in the same order, the pinned role being
entry 12 of 13 on both. No producer change was needed.

## Running it on the phone

The phone path is the **in-app probe**, not a host-driven binary:
`Cyanide/CNDPhysicalKCall1Probe.{h,m}`, launched by the app's own
`--kcall1-probe` argument (`Cyanide/AppDelegate.m:105-116`, the same shape
as `--iouserethernet-signer-probe`). It runs the canary in-process on the
app's own kexploit KRW — `kreadbuf` / `kwrite64` /
`kexploit_early_kwrite32bytes_checked`, with the base from `g_kernel_base` /
`g_kernel_slide` — and resolves processes and ports with the app's own
device-correct helpers (`proc_find_by_name`, `proc_self`,
`proc_get_cred_label`, `task_get_ipc_port_kobject`). There is no provider,
no root, no SSH, no socket, no `pgrep`, and never the VM syscall-439 backend
(`cnd_lab_kernel_call`).

Every address in the route table above is a literal in the probe
(`CNDPhysicalKCall1Static*`, pinned by
`scripts/tests/test_physical_kcall1_probe.py` against this record's tables),
and the three borrowed stubs are additionally byte-checked against the
pinned image at run time (`CNDPhysicalKCall1Expected*`), so the run refuses
rather than proceeds on a mismatch.

1. Build the app for the device and install it. The project's synchronized
   folder picks up the new source; no project edit is needed.
2. Either tap **Settings → Probes → Run IOUserEthernet KCall1 Canary**, or
   launch it with `--kcall1-probe` (the same launch mechanism the other
   physical probes use). The row lives in its own `Probes` root section
   rather than in Quick Actions: `RootSectionActions`' row count is a
   deliberate pin that keeps the Hail Mary / icon-redirect diagnostics
   retained but unexposed, so the probe row does not widen that section.
   Either entry point runs the same probe; the row adds a confirmation
   alert and the inline activity log.
3. The verdict is the app's own report:
   `Documents/CNDPhysicalKCall1Probe.json` in the app container, plus a
   `[CND_KCALL1] result=... success=... report=...` NSLog. Pull it with:

```sh
xcrun devicectl device copy from --device "$CND_DEVICE_ID" \
  --domain-type appDataContainer --domain-identifier com.zeroxjf.ios-cyanide1 \
  --source Documents/CNDPhysicalKCall1Probe.json \
  --destination "$CND_CAPTURE_DIR/CNDPhysicalKCall1Probe.json"
```

`result` is `physical-krw-kcall1-chosen-pc-chosen-x0` only when the
`SIOCADDMULTI` trigger returned `-1` with `errno == EINPROGRESS` *and* every
field, the GOT and the label were restored and read back. A refusal or a
failure names where it stopped (`refused-*`, `canary-setup-refused`,
`canary-stage-refused`, `trigger-failed`, `critical-restore-failure`).

The probe's report carries its own schema
(`com.zeroxjf.cyanide.physical-kcall1-probe` v1): the producer's
`ifnetKCall1*` observation keys plus explicit `kernelReadUsed`,
`kernelWriteUsed` and `kernelCallUsed: NO`, `krwSource` and `baseSource`. It
is not shaped for the shared `validate_result` (which is strict about the
producer's `schema`, `schemaVersion`, `providerOperations` and
`observedKernelBase`), so read the named fields directly. **Open
integration question:** whether to add an adapter so the in-app report also
passes the shared validator.

Nothing has run on the phone yet: that run is what turns any address in this
record from implemented into physical-proved.

### Earlier flow (rejected 2026-10-16; kept for reference)

The first phone attempt was a standalone host-driven pair: a provider
serving KRW over a socket to the producer `.m` run as root on the phone.

```sh
xcrun --sdk iphoneos clang -arch arm64e -Wall -Wextra -Werror -I Cyanide/kexploit \
  scripts/lab/cnd_provide_tfp0.c -framework Foundation -o build/cnd_provide_tfp0
xcrun --sdk iphoneos clang -arch arm64e -Wall -Wextra -Werror -I Cyanide/kexploit \
  scripts/lab/cnd_iouserethernet_krw_trigger.m \
  -framework Foundation -framework IOKit \
  -o build/cnd_iouserethernet_krw_trigger
# then on the phone, as root:
#   /var/tmp/cnd_provide_tfp0 auto /var/tmp/cyanide-kcall-research.sock
#   /var/tmp/cnd_iouserethernet_krw_trigger \
#     /var/tmp/cyanide-kcall-research.sock auto "$(pgrep -x bluetoothd)" \
#     --ifnet-kcall1-pac-canary
```

The owner rejected it: the phone run must use the app's own kexploit KRW the
way the earlier physical probes do, not a provider plus root plus SSH plus a
socket plus `pgrep bluetoothd`. The two signed binaries in `build/` are that
flow's artifacts and take no part in the in-app path.
`scripts/lab/cnd_physical_kcall1_krw.py` likewise stays as host-side
verification only (`scripts/tests/test_physical_kcall1_krw.py`): route and
layout tables, the producer-block agreement check, and the fail-closed
gates.
