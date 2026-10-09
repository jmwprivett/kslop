# VM guide

This is the reproducible, VM-only path for Cyanide's bounded lab kernel-call
provider. It was last exercised on 2026-10-07 against the visible
`cyanide-ios26-base` VM running iOS 26.0 (`23A341`). It is not a physical-device
kcall path and must not be used as evidence that one exists.

The critical rule is that the kernel address is boot-specific. Always obtain
it from the current VM's debugger stub. Never copy an address from an earlier
boot or attempt to discover the slide by reading speculative kernel addresses.

## Start the VM visibly

Run the launcher in a terminal and keep it open. Do not add `--headless`:

```sh
CND_VPHONE_CLI_ROOT=/path/to/vphone-cli-1.0.13
"$CND_VPHONE_CLI_ROOT/.build/vphone-cli.app/Contents/MacOS/vphone-cli" \
  vm launch \
  --library-root "$HOME/Library/CyanideVPhoneLab/VMs" \
  cyanide-ios26-base \
  --variant jb \
  --kernel-debug-port 62139 \
  --project-root "$CND_VPHONE_CLI_ROOT"
```

Wait for the launcher to report the guest IP. The SSH port is `22222`; the
kernel debug port above is local host port `62139`.

## Verify the guest before trusting a new IP

The known-hosts file is:

```text
~/Library/CyanideVPhoneLab/evidence/phase6/ssh_known_hosts
```

The known vPhone ECDSA host-key fingerprint is:

```text
SHA256:WGFlxCgTIy0TNBJYooUcFrV92cov+IS+INSitE5Cz9o
```

For an IP not already in the file, compare the key before adding it:

```sh
VM_IP=192.168.64.76
ssh-keyscan -p 22222 -t ecdsa "$VM_IP" 2>/dev/null | ssh-keygen -lf -
```

Do not accept a changed fingerprint without independently proving that the
endpoint is the intended VM.

## Ensure Cyanide is launchable

The provider socket lives inside the currently running Cyanide data container,
so Cyanide must be open before arming the provider. If iOS reports that Cyanide
cannot be verified after a VM reboot, dismiss the alert and repair only the VM
copy while preserving its existing entitlements. First open the verified root
shell from the host:

```sh
ssh -p 22222 \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$HOME/Library/CyanideVPhoneLab/evidence/phase6/ssh_known_hosts" \
  root@"$VM_IP"
```

Then run this inside the guest:

```sh
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
```

Run those commands in a root shell inside the disposable VM only. The repair
is reversible by reinstalling Cyanide. Do not hard-code the application bundle
UUID; it changes across installations.

## Build, arm, and verify kcall

Set the root password in the environment without placing it in shell history,
then use the debugger-port option rather than supplying a remembered address:

```sh
read -rs 'CND_VPHONE_ROOT_PASSWORD?VM root password: '
export CND_VPHONE_ROOT_PASSWORD
printf '\n'

VM_IP=192.168.64.76
python3 scripts/lab/cnd_vphone_krw.py restart \
  --host "$VM_IP" \
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

A successful run reports all of the following:

```text
debugger kernelUUID=<UUID> loadAddress=<boot-specific-address>
ready capabilities=0xf kernelCall=available smoke=passed ... result=0
ready process=SpringBoard ... readback=yes close=yes kernelCall=available
ready process=iconservicesagent ... readback=yes close=yes kernelCall=available
provider ready ...
```

Treat anything less as a failed arm. Capability `0xf` means process resolve,
direct task, kernel read/write, and kernel call were all independently
validated. The smoke test parses the live fileset, restricts its search to the
kernel's `__TEXT_EXEC`, selects an inert compiler-generated return stub, invokes
it through vPhone syscall 439, and verifies the exact result.

To inspect the current provider without restarting it:

```sh
python3 scripts/lab/cnd_vphone_krw.py status --host "$VM_IP"
```

## Hard safety boundaries

- Never reuse a debugger load address after a reboot.
- Never read the unslid address `0xfffffe0007004000` directly. A prior direct
  read reached vPhone's physical aperture and panicked the VM.
- Never scan or brute-force speculative kernel addresses. The provider's safe
  fallback enumerates mapped regions; the debugger route is preferred.
- Never infer kcall from tfp0/KRW alone. Require capability `0xf` and the
  isolated `smoke=passed` result on every boot.
- Never broaden the VM syscall-439 backend into a physical-device claim. The
  current backend accepts a target plus at most seven arguments and exists only
  in the vPhone jailbreak kernel.
- Never use `--headless` when interactive/visible verification is requested.

## Recovery after a VM panic or reboot

1. Stop the old launcher with Ctrl-C if it is still present.
2. Relaunch visibly with the same debug-port option.
3. Record the new guest IP and verify its SSH host-key fingerprint.
4. Repair and open Cyanide only if iOS rejects its stale developer signature.
5. Run the `restart --kernel-debug-port 62139` command. It captures a fresh
   address; no value from the failed boot is reused.

For the successful 2026-10-07 boot, the kernel UUID was
`03A93373-6498-3F25-8975-04DED251AF1F` and LLDB reported load address
`0xfffffe0041ac4000`. These values are retained only as historical evidence;
they are not inputs for a future run.
