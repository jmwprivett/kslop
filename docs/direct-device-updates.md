# Install Cyanide updates directly to a physical device

Run this build, sign, and install workflow from the repository root on a Mac paired with your device. It installs the signed `.app` directly; no IPA packaging is required.

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

## Build, sign, verify, and install

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
