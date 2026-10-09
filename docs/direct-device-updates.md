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
the exact artifact as the latest verified device build. Then run:

```sh
./scripts/install-device.sh
```

The install script does not build, modify, or re-sign the artifact. It validates
the latest successful artifact recorded by the build script, including its
bundle, provisioning profile, architectures, library link, and signatures. It
then gracefully stops an existing Cyanide process, installs the app with
CoreDevice, verifies device registration, and leaves the app closed. Installing
this way updates the app bundle without intentionally clearing its data
container.

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

xcrun devicectl device install app --device "$DEVICE_ID" "$APP"
```

Wait for the successful installation result before opening Cyanide on the device. If signing or installation reports an expired profile, missing identity, or entitlement mismatch, supply a current matching profile and identity before retrying.

## After installation

Installing an update replaces the app bundle. Runtime settings and separately applied themes are managed within the app.
