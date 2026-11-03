# IOSurface notification race V7 lifetime witness

Date: 2026-11-02 (America/Toronto)

## Outcome

V7 directly proved the pointer lifetime hypothesized from the exact 23A341
disassembly. Two hardware breakpoints observed the same
`IOSurfaceRootUserClient *` first at teardown and later at notification
delivery:

| Observation | Value |
| --- | --- |
| Client at teardown | `0xfffffe250deddb60` |
| `client+0xd8` before the clearing store | `0xfffffe30a2a9ca10` |
| Client at delivery | `0xfffffe250deddb60` |
| `client+0xd8` immediately before delivery's load | `0x0` |

LLDB stopped at live address `0xfffffe002feee53c`, the verified runtime form
of static `0xfffffe00090a653c` (`ldr x0, [x0, #0xd8]`). Detaching allowed the
original path to continue. It immediately produced the expected
`IOLockLock(NULL)` panic with `FAR=0x8`; panic register `x22` contains the same
client pointer, `0xfffffe250deddb60`.

This is VM proof of the stale-pointer lifetime and cleared-lock transition. It
is not evidence of controlled replacement, kernel read/write, or a physical
device primitive.

## Exact build and live binding

- Guest: iPhone OS 26.0 (`23A341`), research VM only
- Kernel UUID: `03A93373-6498-3F25-8975-04DED251AF1F`
- IOSurface UUID: `8132EC95-DE46-3731-9931-024187C84DD2`
- IOSurface version: `393.2.9`
- Debugger kernel text load address: `0xfffffe002de50000`
- Static kernel text address: `0xfffffe0007008000`
- Fresh slide: `0x26e48000`
- Teardown breakpoint: static `0xfffffe00090a1d04`, live
  `0xfffffe002fee9d04` (`str xzr, [x19, #0xd8]`)
- Delivery breakpoint: static `0xfffffe00090a653c`, live
  `0xfffffe002feee53c` (`ldr x0, [x0, #0xd8]`)

Both live instructions were disassembled and checked before the breakpoints
were armed. The observer required hardware breakpoints and only read registers
and one eight-byte field; it did not modify registers or kernel memory.

## No-trigger control

Run `20261102015601` used the unchanged V6 race with mode `no-trigger` for 100
iterations:

- probe exit status: `0`
- 100 `phase=N` markers and final `phase=D`: observed
- teardown events: 117 across 33 distinct client pointers
- every observed pre-clear `client+0xd8`: non-null
- delivery events: 0
- lifetime matches: 0

The control confirms that merely installing the observer did not fabricate a
free-to-delivery match.

## Close-first witness run

Run `20261102015801` used mode `close-first` with a 100,000-iteration ceiling.
The final host marker was:

```text
V6 run=20261102015801 iter=15557 phase=B mode=2 add=0 close=0 ao=2 co=1 success=15533 late=2 not_open=12 other=13 close_success=15558
```

There is no matching `phase=A`. The marker says selector 17 returned success,
close completed first (`ao=2`, `co=1`), and the use-count trigger was entered.
The observer recorded 68,344 events before stopping:

- teardown events: 16,595
- delivery events: 51,749
- exact lifetime matches: 1

The matching event is the final line of `actual-events.jsonl` and contains the
pointer/lock tuple in the outcome table.

## Resulting panic

The recovered report is
`panic-full-2026-11-02-015724.0002.ips`, incident
`C8E9AEF2-1058-469A-8153-4580CC871023`.

Runtime values:

- PC `0xfffffe002e958284`
- LR `0xfffffe002feee544`
- FAR `0x8`
- kernel-cache slide `0x26e48000`
- panicked task: PID 850, `iosurface_notify_race_v7_cli`
- IOSurface frames: `0xfffffe002fee5268`, `0xfffffe002fed3644`,
  `0xfffffe002feec134`

Normalization against the matching images produces the established signature:

- PC `0xfffffe0007b10284`
- LR `0xfffffe00090a6544`
- IOSurface LR offset `0x28294`
- IOSurface frame offsets `0x1efb8`, `0xd394`, `0x25e84`

## Probe and evidence boundary

The installed UIKit wrapper was not used for the witness because FrontBoard
launch after reboot was unreliable. The exact archived V6 `run_probe()` source
was compiled unchanged with a two-line command-line `main`, signed temporarily
with the installed app's existing entitlement blob, and executed as `mobile`.
The no-trigger and close-first configurations, race logic, selectors, and UDP
telemetry format were unchanged.

The first background launch that reported `LAUNCH_RC=0` did not execute a new
race: its V6 run ID had already completed, its durable state did not change,
and no new panic report appeared. It is excluded from the evidence.

Preserved evidence:

```text
~/Library/CyanideVPhoneLab/evidence/iosurface-race-v7-20261102/
```

No physical device was touched. No spray, reclaim attempt, kernel write, or
KRW validation was performed.
