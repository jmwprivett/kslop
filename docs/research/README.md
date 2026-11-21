# Research index

Start here. Each topic lists its **source of truth** first; other files in the
topic are supporting evidence or history. Evidence labels follow
[`probe-capability-contract.md`](probe-capability-contract.md):
**implemented ≠ VM-proved ≠ physical-proved**. Never upgrade a claim when
quoting a doc.

Targets: physical iPhone17,2 (iPhone 16 Pro Max) and the iPhone17,3 research
VM, both iOS 26.0 `23A341`, unless a doc says otherwise.

## Rules and runbooks (read before probe work)

| Doc | Use it for |
| --- | --- |
| [`probe-capability-contract.md`](probe-capability-contract.md) | Canonical claim boundary for kernel / physical / VM probes |
| [`vm-guide.md`](vm-guide.md) | Copy/paste VM lab kernel-call runbook and hard safety rules |
| [`../frida-vm-testing.md`](../frida-vm-testing.md) | Version-locked Frida setup and Frida/KRW bridge |
| [`../physical-device-logs.md`](../physical-device-logs.md) | Pulling logs, reports and panics from the phone |
| [`../direct-device-updates.md`](../direct-device-updates.md) | Build, sign and install to the phone |
| [`rea-secure-execution-interface.md`](rea-secure-execution-interface.md) | REA kernel/TXM/SPTM bundle tool |

## Production features (shipping behavior contracts)

| Topic | Source of truth | Supporting |
| --- | --- | --- |
| SnowBoard Remix / IconServices icon theming | [`vphone-ios26-iconservices-persistence-and-consumer-mappings.md`](vphone-ios26-iconservices-persistence-and-consumer-mappings.md), [`../snowboard-remix.md`](../snowboard-remix.md) | `vphone-ios26-icon-descriptor-matrix.md` (per-app descriptor profile), `vphone-ios26-icon-control-flow.md`, `vphone-ios26-applied-state-audit.md`, `vphone-ios26-springboard-cache-invalidation-matrix.md` (SpringBoard invalidation is currently **disabled** in production) |
| Control Center (Pulsar) theming | [`cc-theming-file-backing.md`](cc-theming-file-backing.md) | [`cc-theming-research.md`](cc-theming-research.md) — route research, what was removed from production, rejected canaries |
| Installer queue / pre-post-respring coordinator | [`queued-system-change-coordinator.md`](queued-system-change-coordinator.md) | [`../implicit-state-machines.md`](../implicit-state-machines.md) |
| Calendar (and Clock) icons | [`vphone-ios26-calendar-provider-repair.md`](vphone-ios26-calendar-provider-repair.md) | Rejected routes: `vphone-ios26-clock-calendar-without-process-injection.md`, `vphone-ios26-clock-base-persistence-result.md` (+ `.log`), `vphone-ios26-clock-background-dedicated-route-result.md`, `vphone-ios26-calendar-order-experiment.md` |
| Pulsar artwork assets | [`../pulsar-artwork.md`](../pulsar-artwork.md) | |

## Research topics

| Topic | Source of truth | Supporting / history |
| --- | --- | --- |
| Kernel CVE triage (26.7.2 / 27.2 advisories vs 23A341) | [`kernel-cve-triage-2026-11.md`](kernel-cve-triage-2026-11.md) — ranked KRW candidates; §13 = 27.3b2 / 27.2.1 / 26.7.3 check and diff order; §14 = 26.x same-major campaign, kc_match method, ipc_kobject lead, verdict | |
| CVE-2026-86969 (IOAudioCodecs) | [`cve-2026-86969.md`](cve-2026-86969.md) | |
| CVE-2026-112705 (AppleAVE2) | [`ave2-cve-2026-112705.md`](ave2-cve-2026-112705.md) — closed/negative for KRW on 26.0 | |
| Physical-phone KRW: what works vs VM-only vs refused | [`physical-krw-findings.md`](physical-krw-findings.md) | `entitlement-audit-panic-20261018-iphone17,2.md`, `entitlement-audit-typed-read-design-20261018.md`, `kcall1-phone-derivation-20261016/` (probe derivation only — no kcall capability) |
| IOSurface notification race (VM) | [`iosurface-race-root-cause-23A341-20261102.md`](iosurface-race-root-cause-23A341-20261102.md) | Not yet consolidated. Read in order: `iosurface-race-probe-plan-20261101.md` → root cause → `-v7` … `-v12` → `iosurface-race-krw-derivation-plan-20261103.md` (superseded by V10–V12 verdicts) → `cve-2026-112477-iosurface-race-link-20261103.md` |
| Hail Mary shared-page probe/patch | [`hail-mary-data-page-experiment.md`](hail-mary-data-page-experiment.md) | Not yet consolidated: `hail-mary-probe.md`, `hail-mary-patch.md`, `hail-mary-page-wire-probe.md` (negative), `hail-mary-special-icon-class-redirect.md`, `vphone-ios26-special-icon-class-redirect.md` (see its 2026-10-21 correction), `hail-mary-switcher-library-followup.md`, plus the `*.json` evidence files here |
| Spectrum / Accent colors | [`spectrum-color-file-ram-backing.md`](spectrum-color-file-ram-backing.md) (extends the feasibility note) | `spectrum-accent-dylib-port-feasibility.md` |
| Spotlight experiments | | `vphone-ios26-phase6.md`, `vphone-ios26-spotlight-breakpoint-phase1.md`, `vphone-ios26-spotlight-pdf-reachability.md` |
| SpringBoard resident repair supervisor | | `springboard-resident-repair-supervisor-feasibility.md` |

## Frida / KRW evidence files

Live `23A341` evidence is split so a userland attach, VM kcall, PAC signer
observation, and validator-consumption proof are not conflated:
[`frida-vm-23A341.json`](frida-vm-23A341.json),
[`frida-krw-bridge-23A341.json`](frida-krw-bridge-23A341.json) (read-only checkpoint),
[`frida-krw-kcall-23A341.json`](frida-krw-kcall-23A341.json) (VM-only safe-return stub test — not a kcall capability),
[`frida-krw-pac-signer-23A341.json`](frida-krw-pac-signer-23A341.json) (thread-state signer canary),
[`thread-state-validator-resume-23A341.json`](thread-state-validator-resume-23A341.json) (validator/resume trace),
[`frida-krw-validator-resume-23A341.json`](frida-krw-validator-resume-23A341.json) (Frida-correlated run),
[`rea-secure-execution-runtime-23A341.json`](rea-secure-execution-runtime-23A341.json).

## Conventions for new docs

- One topic, one source-of-truth file. Append dated sections or fold results
  into it instead of creating a new file per experiment run.
- Put the current verdict and evidence level at the top; mark superseded
  claims as corrected rather than leaving two "current" positions.
- Add the file to this index.
