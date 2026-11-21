# Frida-assisted vPhone testing

This repository has a version-locked Frida workflow for the authorized
iOS 26.0 (`23A341`) vPhone research VM. It installs Frida only in the `jb`
guest, keeps the server and host forwarding endpoints on loopback, and proves
the setup with a bounded read-only attach to SpringBoard.

## Setup

Use the privileged vPhone SSH endpoint. Port `22222` is the root research
endpoint; port `22` is the guest's mobile account and cannot operate the
Frida server with the privileges needed for system processes.

```sh
export CND_VPHONE_ROOT_PASSWORD='<VM root password>'
python3 scripts/lab/cnd_frida_vm.py setup --host 192.168.64.116
```

The host address changes between VM boots. Substitute the current address
reported by vPhone. Strict host-key checking remains mandatory; add the new
address to the lab's pinned `ssh_known_hosts` only after verifying that it has
the expected vPhone key.

The setup command:

1. verifies that the SSH target is a vPhone VRESEARCH guest;
2. downloads the official Frida `17.23.3` iOS arm64 package and checks its
   pinned SHA-256 before and after transfer;
3. installs and starts `frida-server` as root on `127.0.0.1:27042`;
4. creates an isolated host virtual environment with matching Frida `17.23.3`
   and `frida-tools` `14.11.0`;
5. opens an SSH control-master tunnel from host loopback to guest loopback;
6. attaches a read-only agent to the one exact SpringBoard process and writes
   the result to `build/frida-vm/state.json`.

The downloaded package, Python environment, state, and tunnel control socket
remain under ignored `build/frida-vm/`. No credentials are written there.

## Fast daily use

Check all layers:

```sh
python3 scripts/lab/cnd_frida_vm.py status --host 192.168.64.116
```

Repeat the bounded SpringBoard attachment:

```sh
python3 scripts/lab/cnd_frida_vm.py smoke --host 192.168.64.116
```

Use the pinned tools through the managed tunnel:

```sh
build/frida-vm/venv/bin/frida-ps -H 127.0.0.1:27042
build/frida-vm/venv/bin/frida -H 127.0.0.1:27042 -n SpringBoard
build/frida-vm/venv/bin/frida-trace -H 127.0.0.1:27042 -p 39
```

Close only the host tunnel when finished; the VM server remains available for
the next tunnel and disappears with the disposable VM boot:

```sh
python3 scripts/lab/cnd_frida_vm.py stop-tunnel --host 192.168.64.116
```

## Role in the REA workflow

Frida is the dynamic userland half of the REA/Ghidra workflow. Use REA/Ghidra
to identify a semantic candidate and Frida to confirm its live userland caller,
arguments, module ownership, and control flow before writing another compiled
probe. Frida does not observe kernel or SPTM execution and does not itself
provide kcall or a PAC bypass. Any result remains VM-proved until the separate
physical experiment records its own evidence.

## Frida/KRW correlation bridge

`cnd_frida_krw_bridge.py` joins the two existing VM facilities without
pretending that Frida can dereference kernel addresses. A host controller
attaches an observation-only JavaScript agent to SpringBoard and takes bounded
kernel snapshots through the existing standalone provider before and after the
checkpoint. The controller requires all of the following identities before it
accepts a result:

- a vPhone VRESEARCH root endpoint on SSH port `22222`;
- `kern.osversion == 23A341`;
- the standalone socket `/var/tmp/cyanide-kcall-research.sock` and its exact
  provider marker;
- an outer `MH_FILESET` at the provider kbase and `com.apple.kernel` exactly
  one `0x4000` page later;
- inner-kernel UUID `03A93373-6498-3F25-8975-04DED251AF1F`;
- Frida `17.23.3`, one SpringBoard process, arm64, and 8-byte pointers.

The VM SSH server does not carry the provider Unix socket successfully with a
StreamLocal forward. The bridge therefore installs a content-addressed stdio
relay. The relay admits only protocol operations `Capabilities`, `KBase`, and
`Read`; write, kcall, task, and process-resolution frames are rejected before
they reach the provider. This restriction is also covered by the focused unit
tests.

Run the negative-control checkpoint and save evidence:

```sh
export CND_VPHONE_ROOT_PASSWORD='<VM root password>'
build/frida-vm/venv/bin/python \
  scripts/lab/cnd_frida_krw_bridge.py snapshot \
  --host 192.168.64.116 \
  --output docs/research/frida-krw-bridge-23A341.json
```

The default regions are the first `0x100` bytes of the outer fileset and inner
kernel headers. Both are expected to remain unchanged. Add a candidate region
with a repeated `--region BASE:LENGTH:LABEL`; `BASE` can be `kbase`, `kernel`,
either plus a hex offset, or an absolute 16-digit kernel address. A run accepts
at most 16 regions, `0x4000` bytes per region, and `0x10000` bytes total. For
example:

```sh
--region kernel+0x123400:0x80:candidate-object
```

Changed aligned words are reported as raw before/after values. The
`possiblePACOrTaggedValue` field is only a high-bit heuristic and is never a
claim that a word is a PAC.

### Gated kcall and PAC boundary proofs

The controller can place either existing bounded provider probe between its
before and after snapshots. These probes do not pass through the read-only
relay, and the evidence says so explicitly.

```sh
# VM-only probe test: safe-return stub. No kernel write, no general kcall.
build/frida-vm/venv/bin/python \
  scripts/lab/cnd_frida_krw_bridge.py kcall-smoke \
  --host 192.168.64.116 --confirm-vm-boundary 23A341 \
  --output docs/research/frida-krw-kcall-23A341.json

# Deterministic thread-state signer canary. Uses temporary scratch writes and
# kalloc/kfree, and requires the canary to report no persistent mutation.
build/frida-vm/venv/bin/python \
  scripts/lab/cnd_frida_krw_bridge.py pac-signer-canary \
  --host 192.168.64.116 --confirm-vm-boundary 23A341 \
  --output docs/research/frida-krw-pac-signer-23A341.json

# Apply a marked state to one disposable child, follow the exact converter
# call site into ml_check_signed_state and back, then require the child to
# resume with that tuple. Uses read-only KRW plus the VM debugger; no kcall or
# kernel write.
build/frida-vm/venv/bin/python \
  scripts/lab/cnd_frida_krw_bridge.py validator-resume-canary \
  --host 192.168.64.116 --kernel-debug-port 62139 \
  --confirm-vm-boundary 23A341 \
  --output docs/research/frida-krw-validator-resume-23A341.json
```

Live `23A341` results on October 14, 2026:

| Evidence | Result | Important boundary |
| --- | --- | --- |
| `frida-krw-bridge-23A341.json` | SpringBoard PID 39 checkpoint plus exact KRW identity proved | Read-only negative control; 0 changed header bytes |
| `frida-krw-kcall-23A341.json` | Safe stub at `0xfffffe00454c4e24` returned normally | VM-only probe test; no kernel write; not a kernel-call capability |
| `frida-krw-pac-signer-23A341.json` | Signer hash was deterministic and bound to state address and control tuple | Signer invoked; validator was **not** invoked; temporary scratch writes only |
| `frida-krw-validator-resume-23A341.json` | Exact converter call site, validator entry, and return carried one saved state/JOP hash; child resumed with marked x16 | VM-proved consumption path; read-only KRW, no kcall or kernel write |

The live resolver also corrected an important VM-only layout assumption. On
this `VPHONE600` build, `thread+0xf8` is `contextData`, `thread+0x100` is
`upcb`, and `thread+0x108` is `uNeon`; the latter equals `upcb+0x130`.
Physical A17+ offsets in the app must not be copied into this VM profile.

This is acceleration infrastructure, not a new exploit primitive. It makes a
REA/Ghidra hypothesis runnable as one command: give the controller the exact
live kernel object range, put a bounded userland trigger in the Frida agent,
and retain its before/after evidence. The validator/resume canary now proves
that the legitimate exception-state application path accepts a changed x16,
returns from the exact validator call, and subsequently resumes the disposable
EL0 child with the same final tuple. This closes the earlier signer-to-consumer
VM gap. It does not establish physical kcall, an arbitrary kernel return, a
general PAC bypass, or SPTM/PPL access; the next transfer problem is reproducing
the same construction using only the physical KRW aperture and stock-reachable
thread-state APIs.
