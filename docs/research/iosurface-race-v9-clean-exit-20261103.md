# IOSurface notification race V9 clean-exit witness

Date: 2026-11-03 (America/Toronto)

## Objective

V9 removes the observation gap left by V8. The close-first probe runs a finite
batch and exits normally while the four-breakpoint allocator observer remains
attached. Delivery is then observed through a long cooldown, and LLDB detaches
only after the race process no longer exists.

The experiment is VM-only and read-only. It does not spray allocations,
attempt controlled replacement, write kernel memory, or claim a kernel
read/write primitive.

## Exact-build binding

- iOS build: `23A341`
- kernel UUID: `03A93373-6498-3F25-8975-04DED251AF1F`
- IOSurface UUID: `8132EC95-DE46-3731-9931-024187C84DD2`
- IOSurface version: `393.2.9`
- kernel load address: `0xfffffe0035aac000`
- measured slide from static kernel text: `0x2eaa4000`

The live instructions were disassembled before the run:

| Role | Static | Live | Instruction |
|---|---:|---:|---|
| deleting-destructor handoff | `0xfffffe000909fc64` | `0xfffffe0037b43c64` | branch to typed free |
| allocator release complete | `0xfffffe000812e490` | `0xfffffe0036bd2490` | `neg x8, x19` |
| class allocation return | `0xfffffe000909fcf4` | `0xfffffe0037b43cf4` | post-call epilogue |
| delivery lock load | `0xfffffe00090a653c` | `0xfffffe0037b4a53c` | `ldr x0, [x0, #0xd8]` |

The typed-allocation descriptor was rebound to live
`0xfffffe00364738c8`; object size remained `0x148`.

## Run contract

Configuration:

```text
run_id=20261102235544
iterations=3000
add_delay_us=0
mode=close-first
```

The observer was armed before launch for one continuous 300-second interval.
The probe started at guest epoch `1793681762`, exited at `1793681805`, and
returned RC 0. Its active duration was 43 seconds, leaving approximately 257
seconds of post-exit observation before LLDB detached.

After detach, the VM remained alive. A process check found no V9 probe, and the
newest panic report remained V8's `2026-11-02 23:31:34` report. The VM was then
shut down normally by the host.

## Probe result

```text
iterations=3000
registration success=2979
registration completed after close=4
not-open=14
other registration errors=7
successful closes=3000
probe RC=0
```

The allocator observer summary was:

| Counter | Value |
|---|---:|
| validated handoffs | 3,513 |
| allocator completions | 3,021 |
| class allocation returns | 3,987 |
| releases invalidated by reuse | 2,903 |
| qualifying delivery callbacks | 0 |
| invalid/collided correlations | 492 |
| pending threads at final stop | 0 |
| unreallocated release records at final stop | 97 |
| matched | false |

## Conclusion

V9 is a clean bounded negative. Four selector-17 registrations completed after
close, but none produced a delivery satisfying all of these conditions inside
the continuous observation interval:

1. validated typed-free handoff;
2. same-thread return from the underlying allocator free;
3. no intervening same-class allocation of the address;
4. delivery in a strictly later LLDB stop generation.

Unlike V8's long-running attempts, V9 did not panic after detach. This confirms
that V8's immediate post-detach panics depended on leaving the race probe
active across detach; they cannot be promoted to allocator-release proof.

V7's same-pointer teardown/delivery witness and the repeated normalized panic
signature remain valid. The narrower claim that delivery was observed after
the allocator returned remains unproved.
