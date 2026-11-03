# VM guide: copy/paste runbook

This is the reproducible, VM-only path for Cyanide's bounded lab kernel-call
provider. It was last exercised on 2026-10-07 against the visible
`cyanide-ios26-base` VM running iOS 26.0 (`23A341`). It is not a
physical-device kcall path and must not be used as evidence that one exists.

Follow the steps in order and stop at the first failed checkpoint. Do not skip
a failed step, substitute an old IP, reuse a kernel address, or improvise a
different SSH port. Commands labeled **host** run on the Mac. The launcher
stays open in **host terminal A**; all other host commands run in **host
terminal B**.

## Non-negotiable rules

1. Start from the Cyanide repository root.
2. Launch the VM visibly. Do not add `--headless`.
3. Obtain the guest IP from the current launch. It changes between boots.
4. Verify and pin the SSH host key before connecting.
5. Open Cyanide and prove that exactly one Cyanide process is running.
6. Let the harness obtain the kernel address from the current debugger stub.
   Never type or reuse a kernel address.
7. Treat the run as successful only when every success line documented below
   appears.

The critical invariant is that the kernel address is boot-specific. Always
obtain it from the current VM's debugger stub. Never copy an address from an
earlier boot or attempt to discover the slide by reading speculative kernel
addresses.

## One-time host setup

The host must be Apple Silicon macOS with Xcode and an iPhoneOS SDK. The
vPhone CLI checkout and `cyanide-ios26-base` VM must already exist. The live
harness also requires `sshpass`; it will fail before contacting the guest if
that command is missing.

From **host terminal B**, at the Cyanide repository root:

```sh
cd /Users/josh/dev/cyanide

test "$(uname -m)" = arm64
command -v python3
command -v ssh
command -v ssh-keyscan
command -v ssh-keygen
command -v sshpass
command -v codesign
xcrun --find lldb
xcrun --sdk iphoneos --find clang

test -x "$HOME/dev/vphone-cli-1.0.13/.build/vphone-cli.app/Contents/MacOS/vphone-cli"
test -d "$HOME/Library/CyanideVPhoneLab/VMs/cyanide-ios26-base"
```

Every command must exit successfully. A silent `test` is a pass. If the
vPhone executable is missing, build its app bundle from the vPhone checkout
with `./scripts/setup_tools.sh` followed by `./scripts/build.sh`. If the
checkout or VM lives elsewhere, set the overrides shown by:

```sh
./scripts/run-vm.sh --help
```

Do not continue until `./scripts/run-vm.sh --help` itself succeeds from the
Cyanide repository root.

## Every boot: the known-good path

### 1. Launch and leave the VM running — host terminal A

Open a dedicated terminal at the Cyanide repository root:

```sh
cd /Users/josh/dev/cyanide
./scripts/run-vm.sh
```

Keep this command and the visible VM window open for the entire session. The
launcher uses guest SSH port `22222` and local kernel-debug port `62139`.
Wait for the VM to finish booting and for the launcher to report the current
guest IP. Do not continue with an IP remembered from another boot.

Checkpoint: the VM UI is visible, the launcher is still running, and the
current guest IP is known.

### 2. Set this boot's variables — host terminal B

Open a second terminal. Replace only the `VM_IP` value with the address from
the current launch:

```sh
cd /Users/josh/dev/cyanide

export VM_IP='192.168.64.REPLACE_ME'
export CND_VPHONE_ROOT_PASSWORD='alpine'
export CND_VPHONE_KNOWN_HOSTS="$HOME/Library/CyanideVPhoneLab/evidence/phase6/ssh_known_hosts"

case "$VM_IP" in
  ''|*REPLACE_ME*|*[!0-9.]*) echo "set VM_IP to the current numeric guest IP" >&2; false ;;
esac
```

Use this same terminal for the remaining host steps. If a new terminal is
opened, set all three variables again.

### 3. Verify and pin the current SSH endpoint — host terminal B

The expected vPhone ECDSA fingerprint is:

```text
SHA256:WGFlxCgTIy0TNBJYooUcFrV92cov+IS+INSitE5Cz9o
```

Run this block unchanged. It creates the known-hosts file if needed, proves
the scanned key has the expected fingerprint, and adds that exact key only
when the file does not already contain it:

```sh
mkdir -p "$(dirname "$CND_VPHONE_KNOWN_HOSTS")"
touch "$CND_VPHONE_KNOWN_HOSTS"
chmod 600 "$CND_VPHONE_KNOWN_HOSTS"

EXPECTED_FINGERPRINT='SHA256:WGFlxCgTIy0TNBJYooUcFrV92cov+IS+INSitE5Cz9o'
SCANNED_KEY="$(ssh-keyscan -p 22222 -t ecdsa "$VM_IP" 2>/dev/null)"
test -n "$SCANNED_KEY"
ACTUAL_FINGERPRINT="$(printf '%s\n' "$SCANNED_KEY" | ssh-keygen -lf - -E sha256 | awk '{print $2}')"
printf 'expected=%s\nactual=%s\n' "$EXPECTED_FINGERPRINT" "$ACTUAL_FINGERPRINT"
test "$ACTUAL_FINGERPRINT" = "$EXPECTED_FINGERPRINT"

PINNED_KEYS="$(ssh-keygen -F "[$VM_IP]:22222" -f "$CND_VPHONE_KNOWN_HOSTS" 2>/dev/null | sed '/^#/d')"
PINNED_FINGERPRINTS="$(printf '%s\n' "$PINNED_KEYS" | ssh-keygen -lf - -E sha256 2>/dev/null | awk '{print $2}')"

if printf '%s\n' "$PINNED_FINGERPRINTS" | grep -Fqx "$EXPECTED_FINGERPRINT"; then
  echo 'SSH key is already pinned'
elif test -n "$PINNED_KEYS"; then
  echo 'refusing to replace an existing different key for this IP' >&2
  false
else
  printf '%s\n' "$SCANNED_KEY" >> "$CND_VPHONE_KNOWN_HOSTS"
  echo 'SSH key pinned'
fi
```

Checkpoint: the printed `expected` and `actual` fingerprints are identical,
and the last line says either `SSH key is already pinned` or `SSH key pinned`.
Do not delete or replace a different existing key merely to make SSH connect;
first independently prove why the endpoint identity changed.

### 4. Prove this is the intended root research guest — host terminal B

```sh
SSHPASS="$CND_VPHONE_ROOT_PASSWORD" sshpass -e ssh \
  -p 22222 \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$CND_VPHONE_KNOWN_HOSTS" \
  root@"$VM_IP" \
  'PATH=/iosbinpack64/bin:/iosbinpack64/usr/bin:/iosbinpack64/usr/sbin:/bin:/usr/bin:/usr/sbin:/sbin; sysctl -n hw.model; uname -a'
```

Checkpoint: the first output line begins with `VPHONE`, and the `uname` line
contains `VRESEARCH`. The harness deliberately refuses any other endpoint.

If this step times out immediately after the IP first appears, wait for the
guest to finish booting and rerun this same step. Do not change the port to
`22`; the provider harness requires root on port `22222`.

### 5. Open Cyanide and prove that it is running — host terminal B

The provider socket lives in the data container of the currently running
Cyanide process. Merely installing Cyanide is not enough: the app must be open
and remain open while the provider is armed.

First open it from the host:

```sh
SSHPASS="$CND_VPHONE_ROOT_PASSWORD" sshpass -e ssh \
  -p 22222 \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$CND_VPHONE_KNOWN_HOSTS" \
  root@"$VM_IP" \
  '/var/jb/usr/bin/uiopen --bundleid com.zeroxjf.ios-cyanide1'
```

Confirm in the visible VM that Cyanide has opened. Then run the harness's
read-only status check:

```sh
python3 scripts/lab/cnd_vphone_krw.py status \
  --host "$VM_IP" \
  --known-hosts "$CND_VPHONE_KNOWN_HOSTS"
```

Checkpoint: the command exits successfully and prints one `appPID=...`, a
current `home=...`, and a `socket=.../tmp/cyanide-lab-krw.sock`. Existing
provider details may be empty or populated; `restart` handles a verified
existing provider.

If status reports `expected one live Cyanide process, observed 0`, look at the
visible VM:

- If Cyanide is on screen, wait two seconds and rerun `status`.
- If Cyanide closed or crashed, reopen it and rerun `status`.
- If iOS says Cyanide cannot be verified, use the repair block in the next
  section, reopen Cyanide, and rerun `status`.
- Do not proceed to `restart` until `status` passes.

If status reports more than one live Cyanide process, stop. Do not choose a
PID manually; close the duplicate launch or reboot the disposable VM so the
harness can identify exactly one current data container.

### 6. Repair a stale VM app signature only when iOS rejects Cyanide

Skip this entire section when Cyanide opens normally. If iOS reports that
Cyanide cannot be verified after a VM reboot, dismiss the alert and run this
block from **host terminal B**. The commands inside the quoted heredoc execute
in the guest; do not paste them into a separate local shell.

```sh
SSHPASS="$CND_VPHONE_ROOT_PASSWORD" sshpass -e ssh \
  -p 22222 \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$CND_VPHONE_KNOWN_HOSTS" \
  root@"$VM_IP" /bin/sh -s <<'GUEST'
APP_LINE=$(/var/jb/usr/bin/uicache -l | \
  /iosbinpack64/usr/bin/grep '^com\.zeroxjf\.ios-cyanide1 : ')
CYANIDE_APP=${APP_LINE#* : }
case "$CYANIDE_APP" in
  /private/var/containers/Bundle/Application/*/Cyanide.app) ;;
  *) echo "refusing unexpected Cyanide path: $CYANIDE_APP" >&2; exit 1 ;;
esac
ENTITLEMENTS=/var/tmp/cyanide-entitlements.$$
/var/jb/usr/bin/ldid -e "$CYANIDE_APP/Cyanide" > "$ENTITLEMENTS" &&
  test -s "$ENTITLEMENTS" &&
  /var/jb/usr/bin/ldid -S"$ENTITLEMENTS" "$CYANIDE_APP/Cyanide"
RESULT=$?
/iosbinpack64/bin/rm -f "$ENTITLEMENTS"
test "$RESULT" -eq 0 || exit "$RESULT"
/var/jb/usr/bin/uicache -p "$CYANIDE_APP"
/var/jb/usr/bin/uiopen --bundleid com.zeroxjf.ios-cyanide1
GUEST
```

Run this only against the disposable VM endpoint proved in step 4. The repair
preserves the installed binary's existing entitlements and is reversible by
reinstalling Cyanide. Never hard-code the application bundle UUID; it changes
across installations. After the app opens, rerun the `status` checkpoint from
step 5.

### 7. Build, arm, and verify kcall — host terminal B

Run exactly this command. Keep using the debugger-port option; do not replace
it with `--kernel-address`:

```sh
python3 scripts/lab/cnd_vphone_krw.py restart \
  --host "$VM_IP" \
  --known-hosts "$CND_VPHONE_KNOWN_HOSTS" \
  --kernel-debug-port 62139
```

The harness performs this sequence:

1. Attaches LLDB to the local kernel debug stub.
2. Requires exactly one kernel UUID and one canonical, 16K-aligned load
   address.
3. Requires LLDB to report a successful detach.
4. Builds and signs the arm64 provider with the existing tfp0 entitlements.
5. Resolves the load address back to a readable fileset header using validated
   KRW, starts the provider, and runs an isolated kcall smoke test.
6. Revalidates bounded direct-task operations for SpringBoard and
   `iconservicesagent`.

A successful run reports all of the following (additional fields may appear):

```text
debugger kernelUUID=<UUID> loadAddress=<boot-specific-address>
ready capabilities=0xf kernelCall=available smoke=passed ... result=0
ready process=SpringBoard ... readback=yes close=yes kernelCall=available
ready process=iconservicesagent ... readback=yes close=yes kernelCall=available
provider ready ...
```

Checkpoint: the command exits with status 0 and every line pattern above is
present. Anything less is a failed arm. Do not describe a partial run as VM
proof, and do not infer kcall from tfp0 or KRW alone.

Capability `0xf` means process resolve, direct task, kernel read/write, and
kernel call were independently validated. The smoke test parses the live
fileset, restricts its search to the kernel's `__TEXT_EXEC`, selects an inert
compiler-generated return stub, invokes it through vPhone syscall 439, and
verifies the exact result.

To inspect the current provider without restarting it:

```sh
python3 scripts/lab/cnd_vphone_krw.py status \
  --host "$VM_IP" \
  --known-hosts "$CND_VPHONE_KNOWN_HOSTS"
```

`status` proves the current app/container and reports provider state; it does
not replace the `restart` smoke test as evidence for the current boot.

## Failure lookup

| Symptom | Meaning | Required action |
| --- | --- | --- |
| `sshpass is required for this lab harness` | Host prerequisite is missing | Install `sshpass`, confirm `command -v sshpass`, and rerun the same step. |
| `Host key verification failed` | The current `[IP]:22222` key is absent or conflicts with an existing pin | Repeat step 3. Never disable strict checking or delete the old pin without independently proving the endpoint change. |
| SSH connection refused or timed out | Guest boot or SSH is not ready, the IP is stale, or the launcher stopped | Confirm terminal A and the visible VM are still running, obtain the current IP again, and repeat steps 2–4. |
| `refusing: the SSH target did not identify as a vPhone VRESEARCH guest` | The IP points to the wrong endpoint or wrong VM variant | Stop. Recover the current IP from the visible `jb` VM launch; do not bypass the identity check. |
| `expected one live Cyanide process, observed 0` | Cyanide is not currently running under the expected bundle ID | Follow step 5; repair the signature only if the VM UI shows the verification error. |
| `expected one live Cyanide process, observed 2` (or more) | The data-container endpoint is ambiguous | Close the duplicate process or reboot the disposable VM. Never select a PID manually. |
| `kernel debugger did not detach` | The LLDB session did not end cleanly | Stop the run. Restart the VM and launcher before another debugger attach. |
| `kernel debugger did not return one load address/UUID` | The current debug stub did not provide an unambiguous boot identity | Confirm port `62139` belongs to terminal A's current launch. If it still fails, restart the VM; never substitute a saved address. |
| `command failed ... xcrun ... clang` or `codesign` | Xcode/iPhoneOS SDK or signing setup is unavailable | Fix the host prerequisite, run the one-time checks again, then rerun `restart`. |
| `lab provider did not become ready` | Provider startup failed after upload | Preserve the complete error output, keep Cyanide open, and diagnose that output. Do not claim a partial success. |
| Any panic, VM reboot, or launcher exit | All boot-specific identity and provider evidence is stale | Follow the full reboot recovery below; never reuse the prior IP or load address. |

When reporting a failure, include the exact command, its complete stdout and
stderr, whether the VM UI and launcher were still open, and the last checkpoint
that passed. Do not summarize it as merely "the VM command failed."

## Recovery after a VM panic or reboot

1. Stop the old launcher with Ctrl-C if it is still present.
2. Relaunch visibly in host terminal A with `./scripts/run-vm.sh`.
3. Obtain the new guest IP; reset `VM_IP` in host terminal B.
4. Repeat SSH key verification and guest identity checks.
5. Open Cyanide; repair it only if iOS rejects its stale developer signature.
6. Require the read-only `status` checkpoint to pass.
7. Run `restart --kernel-debug-port 62139`. It captures a fresh address; no
   value from the failed boot is reused.

## Hard safety boundaries

- Never reuse a debugger load address after a reboot.
- Never read the unslid address `0xfffffe0007004000` directly. A prior direct
  read reached vPhone's physical aperture and panicked the VM.
- Never scan or brute-force speculative kernel addresses. The provider's safe
  fallback enumerates mapped regions; the debugger route is preferred.
- Never infer kcall from tfp0/KRW alone. Require capability `0xf` and the
  isolated `smoke=passed` result on every boot.
- Never broaden the VM syscall-439 backend into a physical-device claim. The
  current backend accepts a target plus at most seven arguments and exists
  only in the vPhone jailbreak kernel.
- Never use `--headless` when interactive/visible verification is requested.
- Never weaken SSH host-key checking, use port `22`, select a process manually,
  or pass a remembered `--kernel-address` to get around a failed checkpoint.

## Evidence boundary

For the successful 2026-10-07 boot, the kernel UUID was
`03A93373-6498-3F25-8975-04DED251AF1F` and LLDB reported load address
`0xfffffe0041ac4000`. These values are historical evidence only. They are not
inputs for a future run.

Keep these evidence classes separate:

- **Implemented**: the code or documentation exists.
- **VM-proved**: the complete success criteria above passed on the named VM
  boot.
- **Physical-proved**: a separate physical-device experiment recorded its own
  complete evidence.

A successful VM run can establish only the second class. It never upgrades a
physical-device claim.
