# Spotlight hardware-breakpoint Phase 1

This VM-only probe establishes the facts needed before Cyanide installs a
resident hardware-breakpoint handler in Spotlight. It is deliberately
observation-only: it installs no breakpoint, changes no IconRendering
instruction, and does not modify the reconstructed `ICRFinalizedIcon` byte.

The probe records:

- IconRendering path, LC_UUID, shared-cache slide, executable region, and the
  nine instructions centered on the proposed breakpoint;
- every execution of `-[ICRFinalizedIcon
  initFromSerializedData:device:error:]`;
- pthread ID, Mach thread name, main-thread status, QoS, thread name, and
  dispatch queue label for every execution;
- the existing breakpoint exception action and `ARM_DEBUG_STATE64` snapshot
  for every unique executing thread;
- occupied breakpoint and watchpoint slots without changing them.

Build only:

```sh
python3 scripts/lab/cnd_spotlight_breakpoint_phase1.py build
```

Inject into the current VM Spotlight process:

```sh
export CND_VPHONE_ROOT_PASSWORD=alpine
python3 scripts/lab/cnd_spotlight_breakpoint_phase1.py run
```

After injection, repeatedly search for eBay, change the query, dismiss
Spotlight, and reopen it. Then collect the report and computed thread summary:

```sh
python3 scripts/lab/cnd_spotlight_breakpoint_phase1.py read
```

For an interactive observation window:

```sh
python3 scripts/lab/cnd_spotlight_breakpoint_phase1.py watch --observe 30
```

Phase 1 passes only when the report shows `contract=verified` and the row
reconstruction sample establishes whether one stable thread handles every
deserialization. Multiple executing threads are not automatically a failure,
but they require the resident installer to cover all of them and account for
future thread creation before Phase 2 can safely arm a breakpoint.
