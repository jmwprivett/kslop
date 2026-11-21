# Install Cyanide updates directly to a physical device

Run this build, sign, and install workflow from the repository root on a Mac paired with your device. It installs the signed `.app` directly; no IPA packaging is required.

## Build, then install

For the checked-in iPinky Max configuration, first build and sign a fresh
artifact:

```sh
./scripts/build-device.sh
```

The build script always compiles the current working tree into a new
timestamped `build/DirectDeviceUpdate-*` directory, embeds the provisioning
profile, signs the nested code and app, and strictly verifies both signatures.
It does not reuse an older `.app` or package an IPA. When it succeeds, it records
the exact artifact as the latest verified device build, deletes that build's
DerivedData, and removes every older `DirectDeviceUpdate-*` directory, so only
one device build is kept on disk. A failed build removes its own partial output
and leaves the previous artifact in place. Then run:

```sh
./scripts/install-device.sh
```

The install script does not build, modify, or re-sign the artifact. It validates
the latest successful artifact recorded by the build script, including its
bundle, provisioning profile, architectures, library link, and signatures. It
then checks whether Cyanide is already installed and whether it is running. A
running Cyanide must answer the authenticated `krw-update-handoff` command from
that exact PID. The reply must prove the full park, defunct protection, exact
launchd anchor, generation ID, handoff serial, and the reusable recovery grant
pair.
Only then does the installer send SIGTERM. After the process exits, the
installer copies `Documents/cnd-termination.json` and requires the same request
ID, PID, generation, serial, `nextProcessArmed=true`, and
`recoverable-anchored` disposition before installing. A missing reply, suspended
process, unsafe disposition, or mere PID disappearance refuses the update.

The app's park-on-exit is a transaction, not a hint. The app proves
the anchor by looking up both launchd fileports, duplicating them, and comparing
their kernel fileglobs against its own live control and RW sockets; a saved
recovery record by itself never counts as holder proof. Termination and respring
preparation additionally require the combined recoverable-pair proof: a direct
write of the complete saved RW filter region through the forged control socket
must succeed, and a read through that same control socket must match the saved
RW state in the same transaction. These are separate write, readback, returned
length, and comparison observations. The final boundary also reads the control
PCB link and checksum independently and requires the saved RW target and the
original recoverable checksum exactly. Full rollback is a separate operation
that restores both original control fields and intentionally makes the pair
non-recoverable. A park that writes or reads back only some of the RW state
never authorizes termination. The parking process uses dedicated
process-local lookup grants for that proof. Initial acquisition issues one
unbound Control/RW lookup bearer pair during its launchd RemoteCall and stores
those strings in both the defaults record and independent handoff backup. Each
successor process consumes the same pair into new process-local handles; it
does not rotate, replace, release, or exhaust the durable strings. After
recovery validates the exact descriptors against the saved PCB/socket
identities, it read-verifies the durable record and backup and proves the exact
launchd holder again. Recovery, rearm, update preparation, and termination
never initialize or tear down launchd RemoteCall. A failed process-local token
consume or failed durable readback preserves local evidence and refuses the
boundary; it is not treated as global token exhaustion. The
independent launchd root file extension is not a KRW recovery prerequisite. On
success the app completes and read-verifies the final anchored parking
transaction before it exits. The committed record is also atomically written and
read-verified as `Documents/CNDKRWRecoveryHandoff.plist`; recovery imports this
same-boot backup only when the defaults record is absent. A malformed or
mismatched backup fails closed. The process holds its action lock through the
parking transaction so KRW admission stays closed until it exits. On
termination the app records its final disposition (`recoverable-anchored`, `safely-rolled-back`,
`unsafe`, or `no-primitive`) and the authenticated update request identity in
`cnd-termination.json` in its data container, exits non-zero on `unsafe`, and
the installer validates that record before modifying the bundle. The next
launch persists the exact recovery
stage under the `krw.recovery-diagnostic.v1` defaults key so a refused probe
after an update can be traced to a token, lookup, fileport, or primitive
failure after the fact. Diagnostic schema version 2 adds bounded symbolic
readiness, checked-operation, and parking stages with integer errno values;
it never includes sandbox tokens, fileport names, or kernel addresses.
A same-boot readiness, readback, holder-lookup, or bearer-consumption failure is
retryable and preserves the recovery record, backup, and anchor witness.
Neither token-consumption failure nor a socket-option rejection proves that launchd
released its fileports, so neither deletes anything. A definitive boot identity
change still makes a record stale enough for another physical acquisition.

No same-boot socket error releases admission. `EBADF`, `ENOTSOCK`, and `EINVAL`
describe only the attempted operation in the current process; none proves that
launchd released both retained fileports. Every rejected or unverifiable park
therefore preserves the primitive record, backup, and anchor witness and blocks
fresh acquisition until a definitive boot change. Historical
`unusable-pair-released` evidence is decoded conservatively as retryable and its
retired anchor marker is not authority to acquire again.

Before changing or closing a live failing process, retrieve evidence with:

```sh
python3 scripts/lab/cnd_live_probe.py krw-diagnostic
```

This authenticated read-only command bypasses readiness/recovery and the
lifecycle action lock. It returns symbolic recovery/socket/anchor/termination
evidence, including separate target-write, actual RW-read, returned-length,
park, readback, and comparison observations. It never returns raw log buffers,
sandbox tokens, fileport names, or kernel addresses.
After the exact preflight and post-exit proofs, the script performs an in-place
same-bundle-ID update with CoreDevice and
verifies device registration. It does not launch the replacement and does not
terminate anything after the install: the app stays closed until you open it. It
never uninstalls Cyanide: uninstalling would delete the data container that
holds the durable KRW recovery record. The launchd-held fileports and that
preserved record are the two halves the next launch needs to recover the same
parked pair.

Registration success is not recovery proof. The installer proves only the
specific termination path that preceded replacement; recovery remains evidenced
by the app itself when the next launch recovers the
parked generation through the persistence owner, and
`python3 scripts/lab/cnd_live_probe.py krw-diagnostic` reports the resulting
stage, disposition, and generation ID. Host tests and a successful unsigned
build remain implementation evidence only.

The pinned device, identity, profile, and entitlements can be overridden with
the `CYANIDE_DEVICE_ID`, `CYANIDE_SIGNING_IDENTITY`, `CYANIDE_PROFILE`, and
`CYANIDE_ENTITLEMENTS` environment variables. Run `./scripts/build-device.sh
--help` and `./scripts/install-device.sh --help` for the variables accepted by
each phase.

`libxpf.dylib` still needs a development signature even though this path does
not use Sideloadly. Cyanide currently links `@loader_path/libxpf.dylib`, and
iOS requires embedded executable code to be signed before its containing app.
The ad-hoc Sideloadly compatibility pre-sign in `scripts/build.sh` is separate
and is not used here.

## Prerequisites

- Xcode and its command-line tools, with the iPhoneOS SDK available.
- The device paired with and trusted by this Mac, unlocked, and available to Xcode; Developer Mode enabled if required.
- The development signing identity and its private key in the Mac's keychain.
- A valid provisioning profile for this app, identity, and device, plus the matching entitlements. Supply these separately; signing credentials and local build artifacts are excluded from Git.

Check the available devices and signing identities:

```sh
xcrun devicectl list devices
security find-identity -v -p codesigning
```

Use the CoreDevice ID and signing identity reported by those commands in the placeholders below.

## Manual build, sign, verify, and install

Run the following in one shell. Choose a new, explicit output directory for each update instead of deleting or reusing existing signed builds. `mkdir` deliberately fails if this example directory already exists; change `UPDATE_DIR` before rerunning.

```sh
set -e
UPDATE_DIR="$PWD/build/DirectDeviceUpdate-$(date +%Y%m%d-%H%M%S)"
IDENTITY="<development-signing-identity>"
DEVICE_ID="<paired-coredevice-id>"
PROFILE="/path/to/embedded.mobileprovision"
ENTITLEMENTS="/path/to/matching.entitlements"

test -f "$PROFILE"
test -f "$ENTITLEMENTS"
mkdir -p "$PWD/build"
mkdir "$UPDATE_DIR"

xcodebuild \
  -project Cyanide.xcodeproj \
  -scheme Cyanide \
  -configuration Debug \
  -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  -derivedDataPath "$UPDATE_DIR/DerivedData" \
  ARCHS='arm64 arm64e' \
  ONLY_ACTIVE_ARCH=NO \
  CODE_SIGNING_ALLOWED=NO \
  build

APP="$UPDATE_DIR/Cyanide.app"
ditto "$UPDATE_DIR/DerivedData/Build/Products/Debug-iphoneos/Cyanide.app" "$APP"
cp "$PROFILE" "$APP/embedded.mobileprovision"

# Sign the embedded library first, then the containing app.
codesign --force --sign "$IDENTITY" --timestamp=none "$APP/libxpf.dylib"
codesign --force --sign "$IDENTITY" --timestamp=none \
  --entitlements "$ENTITLEMENTS" --generate-entitlement-der "$APP"

codesign --verify --strict --verbose=2 "$APP/libxpf.dylib"
codesign --verify --deep --strict --verbose=2 "$APP"

# Do not install this artifact with a raw CoreDevice command while Cyanide is
# running. Publish it as the latest artifact and use scripts/install-device.sh,
# which terminates a running Cyanide normally and lets the process park its own
# KRW pair on the way out.
printf '%s\n' "$APP" > "$PWD/build/DirectDeviceUpdate-latest.txt"
./scripts/install-device.sh
```

Wait for the successful installation result before opening Cyanide on the device. If signing or installation reports an expired profile, missing identity, or entitlement mismatch, supply a current matching profile and identity before retrying.

## After installation

Installing an update replaces the app bundle. Runtime settings and separately applied themes are managed within the app.
