# GLM review — PAC bypass quest & KRW→kcall port quest

Date: 2026-10-13 · Auditor: GLM-5.3 (Refuseless)
Target: iPhone17,2 / iOS 26.0 (23A341) physical + vPhone 23A341 research VM.

The review is split into chunks in **`glm-review/`**:

| Chunk | Contents |
| --- | --- |
| [`00-header.md`](glm-review/00-header.md) | Scope, sources, evidence standard (implemented ≠ VM-proved ≠ physical-proved) |
| [`01-executive-summary.md`](glm-review/01-executive-summary.md) | Two quests, one wall; overall grades |
| [`02-pac-bypass-audit.md`](glm-review/02-pac-bypass-audit.md) | Quest 1: tried-and-closed table, tried-and-won (aperture data pages, `.34`, dispatch redirect, SPTM/thread-state PAC surface), unresolved frontier |
| [`03-pac-not-tried.md`](glm-review/03-pac-not-tried.md) | Quest 1: eight things not yet attempted (unrun canaries, arm64e signing-gadget census, kernel-context pmap signing, writable-data kcall slots, …) |
| [`04-krw-to-kcall-audit.md`](glm-review/04-krw-to-kcall-audit.md) | Quest 2: VM port status (syscall-439, capability `0xf`), XPF arm64e exclusion, `cs_allow_invalid` candidate, KRW state machine, kcall-route table |
| [`05-krw-to-kcall-not-tried.md`](glm-review/05-krw-to-kcall-not-tried.md) | Quest 2: seven not-yet-attempted routes (data-only kcall, signing-gadget hunt, task-right + `thread_convert`, kernel-thread hijack, KRW lease) |
| [`06-cross-quest-observations.md`](glm-review/06-cross-quest-observations.md) | Why the quests are one dependency chain; strengths; the `.34` significance |
| [`07-advice-next-steps.md`](glm-review/07-advice-next-steps.md) | Prioritized 1–7 recommendations and the "do not spend more time on" list |

One-line verdict: **A on evidence discipline and route closure; D on physical execution of last-mile experiments** — the decisive built canaries have zero recorded runs.
