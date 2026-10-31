# Validation defect-class audit — `cnd_iouserethernet_krw_trigger` (all report modes)

Date: 2026-10-15
Round: 4 of the IFNET kcall validation work (read-only; no `.py`/`.m`/test edits)
Scope: `scripts/lab/cnd_iouserethernet_krw_trigger.py` (validator, KDP runners,
driver conclusions), `scripts/lab/cnd_iouserethernet_krw_trigger.m` (producer),
`scripts/tests/test_iouserethernet_krw_trigger.py` (fixtures).
Target build: iOS 26.0 23A341 vPhone layout (`.m:23-25`).

Evidence standard used throughout: **implemented** ≠ **VM-proved** ≠
**physical-proved**. This audit is itself **implemented-level**: it is source
reading only. Nothing here was executed on the VM or the phone. Every
conclusion below is tagged with the level its cited telemetry *could* support,
and with what the repository currently holds as a witness.

Project guardrails that bound every claim in this file:

- `Cyanide/kexploit/CNDLabKernelProvider.h:37-40` — lab kcall is VM-only, never
  routed from physical KRW, target must lie in the validated kernel image, at
  most eight integer arguments.
- `docs/research/vm-guide.md:153-156` — "Never infer kcall from tfp0/KRW
  alone"; "Never broaden the VM syscall-439 backend into a physical-device
  claim."
- `docs/frida-vm-testing.md:68-75` — any Frida/KRW result "remains VM-proved
  until the separate physical experiment records its own evidence."

Two places where the round-4 brief disagrees with the source (source wins):

| Brief said | Source says |
| --- | --- |
| Hard rules live in `docs/frida-vm-testing.md` | The "never infer kcall" / "never broaden" rules are in `docs/research/vm-guide.md:153-156`; `frida-vm-testing.md` carries only the VM-proved boundary statement (`:68-75`) and the gated-proof table (`:127-165`). |
| kcall1 driver conclusion is "near `.py:860-867`" | It is at `.py:921-928`; `.py:860-867` is the remote `chown`/`chmod` + command assembly. |
| Provider "max 8 args" | `CNDLabKernelProvider.h:38-39` says eight; `docs/research/vm-guide.md:155-157` says "a target plus at most seven arguments". The two project docs disagree with each other; the header is the code-adjacent source. |

## Mode inventory

Modes are enumerated from the `require_*` flags of `validate_result`
(`.py:525-533`), the `expected_result` ladder (`.py:589-603`), and the
producer's `result` ladder (`.m:2898-2912`, `.m:563-565`).

| # | Mode (CLI flag) | Success `result` string | Validator block | Producer success predicate | KDP runner |
| --- | --- | --- | --- | --- | --- |
| A | default (no flag) | `krw-borrow-triggered-normal-signer-path` (`.py:603`, `.m:2911`) | common only: `.py:542-605`, `.py:799-802` | `baseSuccess` `.m:2845-2847`, `swapSuccess` stays `true` `.m:2848` | none |
| B | `--notification-target-swap` | `krw-notifier-target-swap-triggered-stock-61de-dispatch` (`.py:594-595`, `.m:2904`) | `.py:606-629` | `.m:2849-2863` | none (`.py:898-899`) |
| C | `--notification-block-canary` | `krw-notifier-block-noop-dispatch-survived` (`.py:597`, `.m:2906`) | `.py:630-643` | `.m:2864-2868` | `run_block_canary_with_kdp` `.py:64-202` |
| D | `--notification-sandbox-canary` | `krw-notifier-sandbox-iazero-dispatch-survived` (`.py:599`, `.m:2908`) | `.py:644-657` | `.m:2869-2873` | `run_sandbox_canary_with_kdp` `.py:205-355` |
| E | `--notification-2abe-73d8-canary` | `krw-notifier-2abe-73d8-dispatch-survived` (`.py:601`, `.m:2910`) | `.py:658-676` | `.m:2874-2881` | `run_2abe_73d8_canary_with_kdp` `.py:358-503` |
| F | `--ifnet-check-multi-pac-canary` | `krw-ifnet-check-multi-arbitrary-target-pac-executed` (`.py:592`, `.m:2902`) | `.py:677-701` | `.m:2882-2891` | none |
| G | `--ifnet-kcall1-pac-canary` | `krw-ifnet-kcall1-chosen-pc-x0-executed` (`.py:590`, `.m:2900`) | `.py:702-798` | `.m:2892-2895` ← `.m:2228-2234` | none |
| H | `--sysctl-pac-census` | `sysctl-pac-census-complete` (`.py:557`, `.m:564`) | `.py:548-572` (early return, skips common) | `.m:563-566` | none |

Producer failure strings the validator never names (all collapse into
"result did not match mode" at `.py:604-605` or an earlier invariant
message): `provider-connect-failed` `.m:2321`, `provider-identity-failed`
`.m:2360`, `kernel-slide-refused` `.m:2370`, `process-identity-refused`
`.m:2401`, `service-ipc-table-resolution-refused` `.m:2415`,
`baseline-unexpectedly-authorized` / `resource-missing` `.m:2439-2441`,
`post-baseline-process-identity-refused` `.m:2464`,
`label-resolution-refused` `.m:2476`, `amfi-object-shape-refused` `.m:2505`,
`critical-label-restore-failed` `.m:2534`, `sysctl-pac-census-invalid`
`.m:565`, `trigger-failed` `.m:2912`. Not a defect, but the operator loses the
producer's stated reason unless they read the raw JSON.

---

## Table 1 — Class × mode matrix

Legend: **PRESENT** (line) / **ABSENT** (construct exists, defect does not) /
**N-A** (mode has no such construct) / **FIXED-r3** (kcall1 only; residual
noted where the fix is partial). "Common" is the shared block every mode
except H passes through (`.py:542-547`, `.py:573-605`, `.py:799-802`).

| Class | Common | A borrow | B target-swap | C block | D sandbox | E 2abe/73d8 | F check-multi | G kcall1 | H census |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **1 Vacuous-equality** (`.get(a) != .get(b)` / absence passes) | PRESENT `.py:546` (`providerOperations` absent → `[]` → passes); PRESENT `.py:587-588` (`baselineOpenKR` absent → `None != "0x…0"` → passes) | N-A (no key-vs-key compare) | PRESENT `.py:627-628` (`notificationBLastIterator` vs `notificationBExpectedIterator`, no presence gate) | N-A in validator; runner uses `trigger[...]` with `KeyError` catch `.py:163-167` — ABSENT | N-A in validator; runner ABSENT `.py:306-316` | N-A in validator; runner ABSENT `.py:459-468` | PRESENT `.py:699-700` (`ifnetPACCallbackTarget` vs `ifnetPACCanaryTarget`, no presence gate) | FIXED-r3 `.py:725-752` presence/type gate; residual cosmetic `.get()` at `.py:788-791, 797` is safe only because of the gate | N-A |
| **2 Type-strictness** (`!=` lets `1`≡`True`, `False`≡`0`; `isinstance(x,int)` admits `bool`) | PRESENT `.py:584-586` (`kernelReadUsed: True` accepts `1`; `kernelCallUsed: False` accepts `0`) | inherits Common | PRESENT `.py:615-617` (`notificationSetupResult: 0` accepts `False`); PRESENT `.py:620-626` (`isinstance(…, int)` admits `True` as `1` for `notificationBCallbacks` / `BServices` / `BCallbacksOnQueueB`) | PRESENT `.py:639-641` | PRESENT `.py:653-655` | PRESENT `.py:669-671`; PRESENT `.py:674-675` (`notification2ABECallbackCount: True` passes) | PRESENT `.py:691-693` (`ifnetPACSetupResult: 0` accepts `False`; `ifnetPACGOTInstallResult: 0` accepts `False`; `ifnetPACReadbackResult: 0` accepts `False`) | **partial** FIXED-r3: `kcall1_int_fields` exclude bool `.py:748-752`; **residual PRESENT** `.py:721-723` — `ifnetKCall1SetupResult: 0`, `SignerStagesResult: 0`, `Result: 0`, `FinalReadResult: 0` accept `False`; `ConstructedArity: 1` accepts `True`; `ifnetKCall1Success: True` accepts `1` | PRESENT `.py:559-561` (`sysctlPACConditionReadResult: 0` accepts `False`; `sysctlPACCandidateCount: 5` is strict by accident); PRESENT `.py:565` (`readResult != 0` accepts `False`); ABSENT `.py:566-568` (`is not True/False` is strict) |
| **3 Hard-coded constants** (validator pins a literal the producer computes or also pins) | PRESENT `.py:581-582` (`"0x0000000000000000"` pins `CNDHex` width `.m:266-268` and `KERN_SUCCESS`); PRESENT `.py:543` schema literal vs `.m:2274`; PRESENT `.py:589-603` all eight `result` strings duplicated from `.m:2898-2911` / `.m:564` | result string only | result string only; `notificationACallbacks: 0` `.py:613` is semantic, not derived | PRESENT `.py:32-34` (`STATIC_TEXT`, `STATIC_NOOP_BLOCK`, `STATIC_NOOP_BLOCK_INVOKE`) duplicate `.m:24-25, 38-41`; note `.py:32` is inner text `…7008000` while `.m:25` is fileset base `…7004000` — consistent only because `.m:2348-2350` enforces the `0x4000` gap; PRESENT `.py:69` page mask `0x3FFF` | PRESENT `.py:35-36` duplicate `.m:34-37` | PRESENT `.py:37-38` duplicate `.m:48-53`; PRESENT `.py:50-51` `_code_pointer` 47-bit mask re-implements `xpaci` (`.m:354-358`) | PRESENT `.py:685` `"0xe4fe"` vs `.m:1328` (both literals, no derivation); PRESENT `.py:688` `ifnetPACTriggerErrno: 8` vs producer `ENOEXEC` symbol `.m:2798, 2891`; PRESENT `.py:689` `"ENOEXEC"` vs `.m:2798` | FIXED-r3 for errno value (bound to `MarkerValue` `.py:781-784` instead of `36`); **residual PRESENT** `.py:713` `"EINPROGRESS"` vs `.m:2213`; `.py:708` `ConstructedArity: 1` vs `.m:2076 @1`; `.py:724` stage tuple `("Stock","Load","Dispatcher")` vs `.m:2096-2098` prefixes | PRESENT `.py:555` and `.py:563` pin `5` while producer computes `records.count` from the candidates array `.m:504-515, 552` |
| **4 Unenforced contradiction pairs** | PRESENT `.m:2283-2285` — `providerOperations` is a *static* declaration (always includes `"Write"`, never `"KernelCall"`), so `.py:546` can never fire against the real producer; it guards fixtures only | ABSENT (no identified pair beyond Common) | PRESENT: `notificationTargetInstalled: True` with `notificationTargetInstallResult != 0` unchecked (producer derives both from `mutationInstallResult` `.m:2646-2654`); `notificationBWaitResult` (semaphore timeout `.m:2737-2739`) unchecked against `notificationBCallbacks >= 1` | PRESENT: `notificationBlockInstalled: True` vs `notificationTargetInstallResult` `.m:2651-2656` unchecked; restored raw action/ref not re-read after `CNDRestoreNotificationBlock` `.m:1750-1771` so `BlockRestored: True` is flag-only | PRESENT: same `InstallResult` pair `.m:2657`; `notificationSandboxCallback` vs `notificationSandboxCallbackRaw` strip relation `.m:1231-1234` unchecked; `SandboxRestored` flag-only `.m:1807-1827` | PRESENT: same `InstallResult` pair `.m:2659`; `notification2ABECallbackCount` not bounded by `notification2ABEEntryCount` `.m:1566-1569`; `2ABE73D8Restored` flag-only `.m:1593-1628` (no final readback fields) | PRESENT: `ifnetPACTriggerResult: -1` with `ifnetPACCleanupResult == 0` unchecked (producer only runs cleanup when ioctl succeeded `.m:1399-1405`); `ifnetPACGOTRestored: True` cannot be cross-checked — no final GOT readback field exists in this mode (contrast `ifnetKCall1FinalGOT` `.m:2226`); `ifnetPACCanaryTarget` not required ≠ `ifnetPACGOTOriginalTarget` `.m:1317-1320`; `ifnetPACSignedCallback` vs `ifnetPACCallbackTarget` strip relation `.m:2790-2793` unchecked | FIXED-r3: failed-stage marker `.py:778-780`, errno↔marker `.py:781-784`, marker↔GOT `.py:785-787`, final↔original `.py:788-798`; **residual PRESENT**: `ifnetKCall1CleanupResult`/`CleanupErrno` `.m:2214-2215` unchecked (same `-1`/`0` pairing as F); producer-level contradiction a reader will see — `ifnetPACGOTReady: false`, `ifnetPACGOTInstalled: false`, `ifnetPACGOTRestored: false` in a successful kcall1 report because `main` reports its own zeroed canary `.m:2569-2579`, not the signer struct inside `CNDRunIfnetKCall1PACCanary` `.m:2039-2040`; and `ifnetPACCanaryTarget` `.m:1320` stays the ENOEXEC stub although the signer target is overwritten per stage `.m:1932` | PRESENT: `sysctlPACReusableDonorCount` `.m:553` not reconciled against the count of records with `static0E2EDonorCandidate: true` `.m:494-495, 525`; `result` ↔ record flags is correctly re-derived `.py:562-571` ≡ `.m:526-529` |
| **5 Fixture/producer drift** (required set copied from fixture, not from `.m`) | PRESENT: `observedKernelBase` is consumed unvalidated at `.py:982` (`result["observedKernelBase"]`) — absent key raises a bare `KeyError`, not `LabError`; no fixture carries it (`test:56-72` etc.) | PRESENT `test:56-72` — 15 keys vs ~45 emitted on this path; `createdInterfaces` fixture items `{registryID, bsdName}` vs producer `{registryID, machPort, path, kernelWrapper, kernelObject, kernelObjectVtable, bsdName?}` `.m:1852-1877` | PRESENT `test:97-124` verbatim ⊇ validator keys; producer-only: `notificationBWaitResult` `.m:2739`, `notificationTargetInstallResult` `.m:2651`, `notificationAKR/BKR` `.m:1107-1108`, `notificationAServices` `.m:2822`, A/B wrapper/target/notifier/vtable/action/ref `.m:1198-1218` — none validated | PRESENT `test:133-155`; runner-required `notificationANotifier`, `notificationBlockAddress`, `notificationBlockInvoke` `.py:163-165` and `createdInterfaces[].kernelObject` `.py:173` are **absent from the fixture** and never unit-tested | PRESENT `test:164-186`; runner-required `notificationSandboxActionRaw`, `notificationSandboxCallback` `.py:306-312` absent from fixture | PRESENT `test:195-220`; runner-required `notification2ABEAdapterRaw`, `notification73D8ReturnRaw` `.py:460-463` absent from fixture; producer emits 16 `notification2ABE*`/`73D8*` fields `.m:1563-1588`, fixture has one | PRESENT `test:255-285`; producer-only: `ifnetPACGOTAddress`, `ifnetPACGOTOriginalRaw`, `ifnetPACGOTOriginalTarget`, `ifnetPACGOTExpectedTarget`, `ifnetPACCanaryInstruction0-2`, `ifnetPACInitIfnetParams`, `ifnetPACSignerInstruction` `.m:1315-1327`; `ifnetPACInterfaceObject`, `ifnetPACBackingIfnet`, `ifnetPACSignedCallback`, `ifnetPACCleanupResult/Errno` `.m:2787-2800` — so GOT identity is **unchecked in F but checked in G** | FIXED-r3 for `ifnetPACGOTAddress` (`test:352`); **residual PRESENT**: fixture `test:293-368` lacks per-stage `RegistryID`, `InterfaceObject`, `BackingIfnet`, `ControllerCookie`, `CallKR` `.m:1898-1916`, `Load`/`Dispatcher` `SignedCallback`, and `ifnetPACGOTOriginalTarget`/`ExpectedTarget`/`CanaryTarget`/`Instruction0-2`/`Discriminator` `.m:1317-1328`; also lacks the always-emitted `ifnetPACBSDName: ""`, `ifnetPACReadbackResult: 2` (ENOENT) `.m:2594, 2786, 2794` | PRESENT `test:229-248`; fixture records have 4 keys vs 29 emitted `.m:469-498`; `sysctlPACReusableDonorCount`, `sysctlPACConditions` `.m:553-561` absent from fixture |

Tag: every cell is **implemented-level** (source reading). None of the
PRESENT cells has been demonstrated against a live report; the matrix says
what the code *admits*, not what the VM has produced.

---

## Table 2 — Producer-shape drift (validator-required vs producer-emitted)

"Required" = key compared or pinned by `validate_result` or dereferenced by
the mode's KDP runner / driver. "Emitted" = assigned on the success path of
that mode in `.m`. Default keys from `.m:2272-2318` are emitted on every path.

| Mode | Required by validator/runner/driver (cite) | Emitted by producer on this path (cite) | Mismatch |
| --- | --- | --- | --- |
| Common | `schema`, `schemaVersion` `.py:542-544`; `providerOperations` `.py:546`; `kernelReadUsed`, `kernelWriteUsed`, `kernelCallUsed`, `borrowInstalled`, `borrowRestored`, `restoreWholeLabelExact`, `selectorInvokedAfterRestore`, `borrowedOpenKR`, `callKR` `.py:573-583`; `baselineOpenKR` `.py:587`; `result` `.py:604`; `createdInterfaces[].bsdName` `.py:799-802`; **`observedKernelBase` `.py:982`** | Defaults `.m:2274-2318`; `observedKernelBase` `.m:2337`; `baselineOpenKR` `.m:2436`; `kernelWriteUsed`/`borrowInstalled` `.m:2518-2519`; `borrowedOpenKR`, `borrowRestored`, `restoreWholeLabelExact`, `labelWriteCount` `.m:2527-2530`; `selectorInvokedAfterRestore` `.m:2604` or `.m:2667`; `callKR`, `controllerCookie`, `scalarOutputCount` `.m:2783-2785`; `interfacesBefore/After`, `createdInterfaces` `.m:2842-2844` | **Validator → producer**: none missing on success. **Producer → validator**: `observedKernelBase` is read by the driver but not required by the validator (bare `KeyError` path). `labelWriteCount` `.m:2530` (restore-write count) is emitted and never checked; `restoreWholeLabelExact` is literally the same boolean as `borrowRestored` `.m:2528-2529`, so pinning both `.py:578-579` adds nothing. |
| A borrow | Common only | Common only | As Common. |
| B target-swap | `.py:607-614` six keys; `.py:620-628` `notificationBCallbacks`, `notificationBServices`, `notificationBCallbacksOnQueueB`, `notificationBLastIterator`, `notificationBExpectedIterator` | `notificationTargetSwapRequested` `.m:2290`; `notificationSetupResult`, `notificationTargetSwapReady` `.m:2565-2567`; `notificationTargetInstallResult`, `notificationTargetInstalled` `.m:2651-2654`; `notificationBWaitResult`, `notificationTargetRestored` `.m:2739-2743`; counters `.m:2820-2829`; swap inventory `.m:1107-1123, 1198-1234` | **Producer-only, unchecked**: `notificationTargetInstallResult`, `notificationBWaitResult`, `notificationAServices`, `notificationAKR/BKR`, `notificationAExistingCount/BExistingCount` `.m:1115-1118`, `notifierInventoryCount` `.m:1198`, A/B `Wrapper/Target/Notifier/Vtable/ActionRaw/Action/TargetRaw/Ref` `.m:1199-1218`. The conclusion string names "the stock signed 61de action" `.py:941-942` but the validator never reads `notificationAAction` `.m:1211` against the expected action `.m:1269`. |
| C block | `.py:632-637` six keys; runner `notificationANotifier`, `notificationBlockAddress`, `notificationBlockInvoke` `.py:163-165`; `createdInterfaces[].kernelObject` `.py:173` | As B for setup; `notificationBlockInstalled` `.m:2655`; `notificationBlockRestored` `.m:2753`; block header fields `.m:1252-1261`; block donor fields `.m:1219-1223` | **Producer-only, unchecked**: `notificationBlockInvokeRaw`, `notificationBlockISA`, `notificationBlockFlags`, `notificationBlockDescriptor`, `notificationBlockActionDonorCount/Donor/ActionRaw`, `notificationTargetInstallResult`. `notificationBlockInvoke` is checked by the runner only (`.py:180`), never by `validate_result`. **Fixture-only**: none; but the fixture `test:133-155` omits every runner-required key, so the runner's correlation path has no unit coverage. |
| D sandbox | `.py:646-651` six keys; runner `notificationANotifier`, `notificationSandboxActionRaw`, `notificationSandboxCallback` `.py:306-312`; `kernelObject` `.py:322` | `notificationSandboxInstalled` `.m:2657`; `notificationSandboxRestored` `.m:2761`; donor fields `.m:1225-1234` | **Producer-only, unchecked**: `notificationSandboxActionDonorCount/Donor`, `notificationSandboxCallbackRaw`, `notificationTargetInstallResult`. Runner accepts any nonzero `notificationSandboxActionRaw` `.py:332` and never checks `_code_pointer(raw) == action` even though it computes `action` `.py:213`. |
| E 2abe/73d8 | `.py:660-667` eight keys; `notification2ABECallbackCount` `.py:674-675`; runner `notification2ABEAdapterRaw`, `notification73D8ReturnRaw` `.py:460-463`; `kernelObject` `.py:474` | `notification2ABE73D8Prepared` `.m:2561`; `notification2ABE73D8Installed` `.m:2659`; `notificationBlockRestored`, `notification2ABE73D8Restored` `.m:2767-2773`; chain fields `.m:1563-1588` | **Producer-only, unchecked**: `notification2ABERegistry/LowerIndex/DispatchCount/EntryCount/Array`, `notification2ABEBlock*` (6), `notification2ABEReturnRaw`, `notification73D8DispatchObject`, `notification73D8DispatchTargetOriginal`. The dispatch object the install mutates `.m:1650-1651` has no post-restore readback field. |
| F check-multi | `.py:679-689` eleven keys; `ifnetPACBSDName` `.py:696`; `ifnetPACCallbackTarget`, `ifnetPACCanaryTarget` `.py:699-700` | `ifnetCheckMultiPACCanaryRequested` `.m:2298`; prepare fields `.m:1315-1328`; `ifnetPACSetupResult`, `ifnetPACGOTReady` `.m:2578-2579`; `ifnetPACGOTInstallResult`, `ifnetPACGOTInstalled` `.m:2661-2665`; `ifnetPACGOTRestored` `.m:2699`; tail fields `.m:2786-2800` | **Producer-only, unchecked**: `ifnetPACGOTAddress`, `ifnetPACGOTOriginalRaw`, `ifnetPACGOTOriginalTarget`, `ifnetPACGOTExpectedTarget`, `ifnetPACCanaryInstruction0-2`, `ifnetPACInitIfnetParams`, `ifnetPACSignerInstruction`, `ifnetPACInterfaceObject`, `ifnetPACBackingIfnet`, `ifnetPACSignedCallback`, `ifnetPACCleanupResult/Errno`. **Shape gap**: no final GOT readback is emitted in this mode, so "restored" is a flag with no raw-value witness (the kcall1 path emits `ifnetKCall1FinalGOT` `.m:2226`). |
| G kcall1 | `.py:703-719` sixteen keys; `.py:727-743` thirteen address fields + two ints + per-stage `Target`/`CallbackTarget`/`ReadbackResult`/`BSDName`; `createdInterfaces[].bsdName` `.py:766-775`; absence of `ifnetKCall1FailedStageSanitized` `.py:778` | `.m:2070-2077`; per-stage nine fields × 3 via `CNDReportSignedIfnet` `.m:1893-1917, 2096-2098`; `.m:2101`; `.m:2136-2140`; `.m:2165-2166`; `.m:2210-2226`; `.m:2234`; `ifnetKCall1Result` `.m:2610`; prepare fields `.m:1315-1328` (via `.m:2040`); failure-only `ifnetKCall1FailedStageSanitized` `.m:2116` | **Validator → producer**: none missing (r3 closed `ifnetPACGOTAddress`). **Producer-only, unchecked**: per-stage `RegistryID`, `InterfaceObject`, `BackingIfnet`, `ControllerCookie`, `CallKR`; `Load`/`Dispatcher` `SignedCallback`; `ifnetKCall1X0Field`, `TargetField`, `CallbackField` `.m:2136-2138` (the validator never checks `TargetField == BackingIfnet+0xb0` / `X0Field == BackingIfnet+0x90`, the two offsets the dispatcher comment `.m:111-115` depends on); `ifnetKCall1CleanupResult/Errno`; `ifnetKCall1LoadTarget`, `ifnetKCall1DispatcherTarget` are required as strings but never compared to `ifnetKCall1LoadCallbackTarget` / `DispatcherCallbackTarget` (only `{stage}Target` ↔ `{stage}CallbackTarget` is compared `.py:759-761`, which is the same pair; the *chosen* targets `.m:2041-2043` are checked only transitively through `SignerStagesResult == 0` ← `.m:2021-2024`). **Stale in producer**: `ifnetPACCanaryTarget` `.m:1320` reports the ENOEXEC stub although the kcall1 signer re-targets per stage `.m:1932`; `ifnetPACGOTReady/Installed/Restored` report `main`'s unused canary `.m:2569-2579`, not the signer's. |
| H census | `.py:549-557` eight keys; `sysctlPACRecords[]` with `readResult`, `handlerTargetMatches`, `listMalformed`, `listCycle` `.py:562-571` | Defaults `.m:2274-2318` (so `kernelWriteUsed: NO` `.m:2281`, `providerOperations` includes `"Write"` `.m:2284`); `providerCapabilities`, `debuggerLoadAddress`, `observedKernelBase` `.m:2335-2337`; `kernelSlide` `.m:2368`; `sysctlPACRecords`, `CandidateCount`, `ReusableDonorCount`, `ConditionReadResult`, `Conditions`, `ReadOnly`, `result` `.m:551-565`; each record 29 keys `.m:469-498` | **Producer-only, unchecked**: `sysctlPACReusableDonorCount`, `sysctlPACConditions.*`, record keys `linked`, `handlerHasPACBits`, `static0E2EDonorCandidate`, `name`, `kind`, `delayedRegistrationBit`, `handler`/`expectedHandler` (the validator trusts the producer's `handlerTargetMatches` instead of re-deriving `handler == expectedHandler`). **Semantic**: `providerOperations` lists `"Write"` on a mode that performs none — the read-only claim rests on `kernelWriteUsed` and `sysctlPACReadOnly`, both of which are declarations, not a log of issued frames. |

Tag: **implemented-level** (source reading).

---

## Table 3 — Claim vs evidence

The repository holds **no saved observation for any mode of this trigger**:
no file matching the `iouserethernet-krw-observation` schema or any of the
eight success strings exists under `docs/research/` or elsewhere (searched
`*.json`, `*.md`, `*.log`). Every row below is therefore **implemented-level
in the repo today**. The "VM-proved" column states what a single
`require_vphone`-gated run (`.py:845`) with `--output` *would* establish;
"physical" is **never** reachable from this tool (`CNDLabKernelProvider.h:
37-40`, `vm-guide.md:155-157`) and is listed only to say so.

| Claim (string / conclusion, cite) | Telemetry that backs it (cite) | Highest level the telemetry can support | Missing witness |
| --- | --- | --- | --- |
| `krw-borrow-triggered-normal-signer-path` `.m:2911`; conclusion "reversible AMFI-label borrowing reached the normal … signer path without kcall" `.py:972-975` | `baselineOpenKR != 0` `.m:2437`, `borrowedOpenKR == 0` `.m:2522-2527`, label restore with verify `.m:2525-2529`, `callKR == 0` and a new interface `.m:2845-2847` | implemented (repo); VM-proved after one saved run | Saved observation; `labelWriteCount` reconciliation; a post-restore label readback field (restore is verify-on-write `.m:1286-1295` but no final bytes are emitted). "Without kcall" rests on `test_source_has_no_kernel_call_operation` `test:475-477`, not on telemetry — `providerOperations` is static `.m:2283-2285`. |
| `krw-notifier-target-swap-triggered-stock-61de-dispatch` `.m:2904`; conclusion `.py:938-942` | observer B callbacks/services/onQueueB ≥ 1, `lastIterator == iteratorB`, observer A == 0 `.m:2849-2863`; restore `.m:2740-2743` | implemented; VM-proved after a saved run — **but only as a userspace-observed delivery**: no KDP witness exists for this mode (`witness=None` `.py:882, 898`) | Kernel-side witness that the *stock* 61de action ran (breakpoint at `CNDStaticUserNotificationAction` `.m:30-31`); `notificationAAction == expected` is checked by the producer `.m:1273-1274` but not surfaced to the validator; `notificationBWaitResult == 0`. |
| `krw-notifier-block-noop-dispatch-survived` `.m:2906`; conclusion "hit the address-authenticated no-op block invoke under a one-shot KDP breakpoint" `.py:945-949` | KDP: `pc == invoke`, `x0 == block`, `x2 == notifier`, `x1` is exactly one created object `.py:176-182`; block header shape `.m:1262-1265`; restore flag `.m:2753` | implemented; VM-proved after a saved run with `kdpWitness` (`.py:987-988`) — the strongest witness in the file | Post-restore readback of `notifierA.action`/`ref` raw words (restore is verify-on-write `.m:1755-1768`, final values not emitted); unit coverage of the runner's correlation (`test:133-155` omits every runner key). |
| `krw-notifier-sandbox-iazero-dispatch-survived` `.m:2908`; conclusion "x0 equal to the newly published IOService" `.py:953-956` | KDP: `pc == callback`, `x0` is the one created object, `x1 == 0`, `x2 == x0`, `x3 == notifier` `.py:326-334`; donor selection `.m:1171-1195` | implemented; VM-proved after a saved run with witness | `rawSignedAction` recorded `.py:343` but never strip-compared to the live action (`.py:332` accepts any nonzero); post-restore readback. |
| `krw-notifier-2abe-73d8-dispatch-survived` `.m:2910`; conclusion "crossed IA/0x2abe into a fixed IA/0x73d8 adapter, hit a signed ret under KDP" `.py:960-963` | KDP: `pc == return_target`, `xpac(x2) == return_target`, `x1` created object `.py:477-480`; fixup raw values strip to expected `.m:1440-1452`; dispatch object primed with the 73d8 ret `.m:1650-1651` | implemented; VM-proved after a saved run with witness | The "crossed 0x2abe adapter" half: the runner records `thread backtrace -c 10` `.py:383` but never parses it, so the adapter frame (`CNDStatic2ABEAdapter` `.m:48-49`) is not demonstrated — only the final `73d8` landing is. Post-restore readback of callback slots and dispatch object (`.m:1593-1628` restores with verify, emits nothing). |
| `krw-ifnet-check-multi-arbitrary-target-pac-executed` `.m:2902`; conclusion "SIOCADDMULTI executed that persisted target without provider kcall" `.py:930-935` | GOT swapped `.m:1341-1351`, new ifnet's `check_multi` strips to the canary `.m:2704-2726`, GOT restored `.m:2697-2699`, `SIOCADDMULTI` → `-1`/`ENOEXEC` `.m:1394-1397, 2890-2891` | implemented; VM-proved after a saved run — via **errno propagation only**, no KDP in this mode | A breakpoint or marker at `CNDStaticENOEXECReturn` `.m:105-107`; a final GOT readback field; the word "arbitrary" is wider than the evidence — one BTI-valid stub was targeted, the signer's willingness to sign *any* raw value is implied by `.m:92-96` but demonstrated for exactly one target here (the kcall1 mode demonstrates three `.m:2083-2094`). |
| `krw-ifnet-kcall1-chosen-pc-x0-executed` `.m:2900`; conclusion "a controlled one-argument kernel call: a signed dispatcher selected a signed BTI-safe callee and replaced x0 with a chosen kernel address; the callee returned the chosen EINPROGRESS marker and every temporary field was restored without provider kcall" `.py:922-927` | Three signer stages `.m:2083-2094` each read back to the chosen target `.m:2021-2024`; dispatcher gadget bytes verified `.m:2054-2068`; GOT word set to `EINPROGRESS` `.m:2147-2148`; `[x0+0xb0] = load gadget`, `[x0+0x90] = GOT address`, `check_multi = dispatcher` `.m:2151-2163`; `SIOCADDMULTI` → `-1`/`EINPROGRESS` `.m:2173-2176, 2228-2229`; final raw readbacks equal originals `.m:2231-2233`; validator binds errno↔marker↔GOT `.py:781-787` and final↔original `.py:788-798` | implemented; VM-proved after a saved run — as **"controlled call of a signer-blessed pc with a chosen x0, arity 1, return observed through errno"**; **never** physical-proved (VM-only provider, `CNDLabKernelProvider.h:37-40`; and the signer here is a kernel path, not the lab kcall, so `vm-guide.md:153` "require capability 0xf and smoke=passed" does not even apply — this is a *separate* VM-only control-flow result) | No KDP witness in this mode (no breakpoint at `CNDStaticLoadW0FromX0` `.m:108-110` or the dispatcher `.m:114-115`); the return value is witnessed only as an errno that the stock `SIOCADDMULTI` path propagates — the chain is **inferred** from (a) marker ≡ errno and (b) the marker living only at the GOT address the chosen x0 points at. `ifnetKCall1ProviderKCallUsed: false` `.m:2077` and `ConstructedArity: 1` `.m:2076` are constants, not measurements. "Every temporary field restored" is backed by raw readbacks (good) — this is the one mode where restoration has a value witness. |
| `sysctl-pac-census-complete` `.m:564`; conclusion "Read-only KRW classified five conditional sysctl OIDs … without kernel writes or provider kcall" `.py:966-969` | Five records with `readResult == 0`, `handlerTargetMatches`, no malformed/cycle `.m:526-529`; condition words read `.m:536-550`; path returns before any write `.m:2376-2381` | implemented; VM-proved after a saved run — as a **classification**, not a control-flow result | "Without kernel writes" is a declaration (`kernelWriteUsed: NO` default `.m:2281`; `sysctlPACReadOnly: YES` `.m:562`); the provider's `providerOperations` list still names `"Write"` `.m:2284`. A frame-level log from the provider side would be the real witness. `handlerHasPACBits` `.m:493` and `static0E2EDonorCandidate` `.m:494-495` are emitted but the validator never reads them, so the "PAC state" half of the conclusion is unvalidated. |
| Driver `classification: "vm-runtime-observed"` `.py:979` (all modes) | `require_vphone(ssh)` `.py:845`; standalone socket present `.py:846-847` | VM-gated label — fine as a label; it is **not** evidence of anything mode-specific | When `--kernel-address` is used, `kernelUUID` is `"not-captured"` `.py:825, 980`, so the observation is not bound to a kernel identity even though the producer checked fileset/header identity `.m:2338-2365`; the producer's `kernelSlide`, `providerCapabilities`, `debuggerLoadAddress` are emitted `.m:2335-2368` and not echoed. |

Tag: **implemented-level** for every row (no run artifacts in repo).

---

## Round-5 fix list (recommendations only; no edits made)

Priority order is by how many modes a single change closes.

1. **Shared helpers, applied to every mode** (closes class 1 and class 2 in
   Common, B, C, D, E, F, H and the residual in G):
   - `require_int(value, key, *, expected=None)` — `isinstance(v, int) and not
     isinstance(v, bool)`; reject `False` for `…Result: 0`, `True` for
     `…Count`/`Arity`.
   - `require_bool(value, key, expected)` — `v is expected` (the `.py:566-568`
     idiom, generalised).
   - `require_str(value, key, *, pattern=None)` — non-empty, optional
     `0x[0-9a-f]{16}` regex for `CNDHex` fields (`.m:266-268`).
   - `bound_equals(value, a, b)` — both keys present, same type, equal; replaces
     `.py:627-628`, `.py:699-700`, and the gated `.get()` at `.py:788-797`.
   - `distinct_members(value, keys)` — lift `.py:762-765`.
   - `no_contradiction(value, [(pred_a, pred_b, message)])` — express the
     pairs in Table 1 row 4 as data: `Installed ⇒ InstallResult == 0`
     (B/C/D/E), `TriggerResult == -1 ⇒ CleanupResult == -1` (F/G),
     `Restored ⇒ Final == Original` (F once a final-GOT field exists).
   Replace the `required = {…}; for key, expected … if value.get(key) !=
   expected` idiom (`.py:549-561, 573-586, 607-619, 631-643, 645-657,
   659-673, 678-695, 703-723`) with these helpers so the type check is not
   opt-in.

2. **Producer-derived required-key sets** (closes class 5 everywhere): add a
   test that parses `.m` for `report[@"…"]` / `CNDReportSignedIfnet` prefixes
   and the `.m:2272-2318` default dictionary, builds the per-mode emitted set,
   and asserts (a) every validator-required key ⊆ emitted-on-that-path and (b)
   every fixture key ⊆ emitted. Today the fixtures are verbatim copies of the
   required sets (`test:56-368`), so a validator that drifts from the producer
   still passes its own tests. Also add `observedKernelBase` to the common
   required set (`.py:982` bare `KeyError`).

3. **Derive the pinned literals from one place** (class 3): import or parse
   the eight `result` strings, `"0xe4fe"`, `ENOEXEC`/`EINPROGRESS` names, and
   the six `STATIC_*` addresses (`.py:32-38`) from the `.m` source in a test,
   as `test_source_has_no_kernel_call_operation` already does for identifiers
   (`test:475-516`). Replace `ifnetPACTriggerErrno: 8` with `errno.ENOEXEC`
   and bind name↔value the way G does (`.py:781-784`).

4. **Give the KDP runners fixtures and a seam** (class 5, C/D/E): factor the
   post-run correlation at `.py:161-185`, `.py:304-337`, `.py:457-487` into
   pure functions `(trigger_json, registers, transcript) -> witness` and unit
   test them with fixtures carrying `notificationANotifier`,
   `notificationBlockAddress`, `notificationSandboxActionRaw`,
   `notification2ABEAdapterRaw`, `createdInterfaces[].kernelObject`. Add
   `xpac(rawSignedAction) == action` to D (`.py:332`) and parse the backtrace
   for the adapter frame in E (`.py:383`).

5. **Producer-side shape fixes to request (not for the validator to paper
   over)** — flagged for the `.m` owner, not changed here: emit a final GOT
   readback in F (mirror `.m:2195-2226`); in G stop re-reporting `main`'s
   unused canary at `.m:2578-2579` and refresh `ifnetPACCanaryTarget` per stage
   or drop it; consider making `providerOperations` a log of issued frames
   rather than a static capability list (`.m:2283-2285`) so the `.py:546`
   guard means something against a live report.

6. **Claim wording** (Table 3): rename or qualify
   `krw-ifnet-check-multi-arbitrary-target-pac-executed` → the evidence shows
   one chosen BTI stub; keep "chosen" (as G does) rather than "arbitrary". For
   G, state in the conclusion that the return value is witnessed through
   `SIOCADDMULTI` errno propagation and that the mode has no KDP witness.

Nothing in this round changes evidence levels: all eight modes remain
**implemented** in the repository until a `--output` observation is saved;
each then becomes **VM-proved** for exactly the witness its row names; none
can become **physical-proved** through this tool.
