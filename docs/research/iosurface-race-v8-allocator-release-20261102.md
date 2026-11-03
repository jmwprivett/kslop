# IOSurface notification race V8 allocator-release witness

Date: 2026-11-02 (America/Toronto)

## Objective

V8 tests one bounded question left open by V7: does notification delivery use
the same `IOSurfaceRootUserClient *` after the typed allocator release routine
has returned for that object?

The experiment remains VM-only and read-only. It does not spray allocations,
attempt address replacement, write kernel memory, or claim a kernel read/write
primitive.

## Exact-build static binding

The inspected images match the V7 and panic evidence:

- kernel UUID: `03A93373-6498-3F25-8975-04DED251AF1F`
- IOSurface UUID: `8132EC95-DE46-3731-9931-024187C84DD2`
- IOSurface version: `393.2.9`

The `IOSurfaceRootUserClient` metaclass constructor passes object size `0x148`
at static `0xfffffe000909f8d8`. Its generated allocation and deletion paths use
the same typed-allocation descriptor at static `0xfffffe00079cf8c8`:

```text
0xfffffe000909fce4  adrp x0, 0xfffffe00079cf000
0xfffffe000909fce8  add  x0, x0, #0x8c8
0xfffffe000909fcec  mov  w1, #0x148
0xfffffe000909fcf0  bl   0xfffffe000812e3ec
```

The deleting destructor starts at static `0xfffffe000909fc24`. After the class
destructor it supplies the exact descriptor, object pointer, and size to the
typed release routine:

```text
0xfffffe000909fc38  bl   0xfffffe000909fae4
0xfffffe000909fc3c  adrp x0, 0xfffffe00079cf000
0xfffffe000909fc40  add  x0, x0, #0x8c8
0xfffffe000909fc44  mov  x1, x19
0xfffffe000909fc48  mov  w2, #0x148
0xfffffe000909fc64  b    0xfffffe000812e450
```

The typed release routine calls the applicable underlying allocator free at
static `0xfffffe000812e484` or `0xfffffe000812e48c`. Both paths converge at
static `0xfffffe000812e490`, the first instruction after that call returns.
This gives V8 an unambiguous completion boundary rather than treating the V7
`client+0xd8` cleanup as object deallocation.

## Observer contract

`scripts/lab/cnd_lldb_iosurface_release.py` uses four hardware breakpoints,
all rebound with the current boot's freshly measured slide:

1. static `0xfffffe000909fc64`: validate descriptor, client, and size at the
   exact deleting-destructor handoff;
2. static `0xfffffe000812e490`: on the same kernel thread, record that the
   underlying allocator release call returned;
3. static `0xfffffe000909fcf4`: observe the return from this class's exact
   typed-allocation wrapper and invalidate a release record if that address is
   reused;
4. static `0xfffffe00090a653c`: record notification delivery's client pointer
   and stop only if it matches a completed, unreallocated release.

The generic completion breakpoint stays armed so the first completion on a
kernel CPU cannot be lost to debugger breakpoint-enable latency. Its callback
returns immediately for a thread without a validated handoff. Callbacks read
registers and one eight-byte field at `client+0xd8`; they do not alter
registers or kernel memory. Every event also records LLDB's process stop ID.
A delivery qualifies only when its stop ID is strictly greater than the
allocator-completion stop ID. A same-stop multicore hit is rejected.

The delivery breakpoint is disabled when no completed, unreallocated release
exists. When releases exist, its condition is restricted to those addresses.
This avoids fabricating ordering from normal delivery traffic and prevents the
debugger from being dominated by irrelevant delivery callbacks.

## Live result

**V8 did not obtain the strict allocator-release witness.** The bounded result
is negative. It does not weaken V7's teardown/lifetime witness, but it does not
upgrade that result to allocator-release-proven UAF.

### Rejected observer candidates

Two early candidates identified necessary observer corrections and are not
counted as proof:

1. A no-trigger candidate placed allocator completion and delivery in the
   same all-CPU LLDB stop. Stop-generation tracking now rejects it.
2. An add-first control produced release stop ID 2681 and delivery stop ID
   2761 for address `0xfffffe197d3a8e70`, but `client+0xd8` contained a valid
   nonzero lock. Static and live follow-up showed legitimate address reuse.
   Allocation-return tracking now invalidates such release records.

### Clean-order control

The final add-first control completed 100 iterations without a match:

| Counter | Value |
|---|---:|
| allocation returns | 254 |
| validated handoffs | 183 |
| completed releases | 112 |
| releases invalidated by reuse | 43 |
| qualifying deliveries | 0 |
| matched | false |

The probe reported 100 successful registrations, zero registrations after
close, and 100 successful closes. This control is the expected clean ordering.

### Close-first attempts

All addresses below were derived from a fresh kernel load address for that
boot and live-disassembled before use. No historical runtime address was
reused.

| Attempt | Capture | Handoffs | Completions | Allocations | Reuse invalidations | Qualifying deliveries | Result |
|---|---:|---:|---:|---:|---:|---:|---|
| actual 1 | 300 s | 11,316 | 8,485 | 13,969 | 8,028 | 0 | negative |
| actual 2 | 2 x 300 s, continuous | 12,167 | 9,656 | 16,014 | 9,284 | 0 | negative |
| actual 3 | 12 x 60 s, continuous | 957 | 567 | 1,596 | 389 | 0 | negative |

The shorter windows in actual 3 deliberately resumed the target under LLDB
between bounds, so a free pending at a boundary could complete while all four
breakpoints remained armed. No strict match occurred.

### Post-detach panics

Each long-running probe reproduced the established null-lock panic immediately
after the final LLDB detach. Those panics are preserved, but they are not the
requested V8 witness because delivery occurred outside the observer interval.
All three normalize to the already-established signature:

```text
PC  0xfffffe0007b10284
LR  0xfffffe00090a6544
FAR 0x8
IOSurface UUID 8132EC95-DE46-3731-9931-024187C84DD2
kernel UUID    03A93373-6498-3F25-8975-04DED251AF1F
```

The event logs explain why the gap matters:

- actual 1's panic client had a completed-release record and no later observed
  allocation inside the window, but delivery was post-detach;
- actual 2 stopped with its eventual panic client at the typed-free handoff,
  before allocator completion was observed;
- actual 3's eventual panic client had recent allocation observations but no
  later completed release inside the captured interval.

None of those sequences satisfies completion, no intervening allocation, and
strictly later delivery entirely inside one continuous observation interval.

## Conclusion

V8 provides useful instrumentation and a strong negative boundary:

- address reuse is common enough that pointer equality after a historical free
  is not sufficient;
- same-stop multicore breakpoint coalescing is not temporal ordering;
- the crash remains reproducible with the exact normalized signature;
- allocator-release-before-delivery was **not** VM-proved by these runs.

There was no spray, controlled reclaim, kernel-memory write, physical-device
test, or kernel read/write claim.

## V9 clean-exit follow-up

V9 removed V8's final-detach gap by limiting the close-first probe to 3,000
iterations. The probe exited normally after 43 seconds while the same observer
remained attached for approximately 257 additional seconds. It recorded four
registrations completed after close, zero qualifying deliveries, and no panic
after detach. See
`docs/research/iosurface-race-v9-clean-exit-20261103.md`.

This clean bounded negative confirms that V8's post-detach panics cannot be
used as allocator-release proof: those runs detached while the race process
was still active.
