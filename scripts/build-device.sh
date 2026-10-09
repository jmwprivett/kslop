#!/usr/bin/env bash
# Build and sign the current Cyanide working tree for direct device install.

set -euo pipefail

cd "$(dirname "$0")/.."

REPO_ROOT="$PWD"
PROJECT="${CYANIDE_PROJECT:-Cyanide.xcodeproj}"
SCHEME="${CYANIDE_SCHEME:-Cyanide}"
CONFIGURATION="${CYANIDE_CONFIGURATION:-Debug}"
BUNDLE_ID="${CYANIDE_BUNDLE_ID:-com.zeroxjf.ios-cyanide1}"
IDENTITY="${CYANIDE_SIGNING_IDENTITY:-AD6C2216FF76B8581482BC09A86B07F76BAB84CC}"
PROFILE="${CYANIDE_PROFILE:-$REPO_ROOT/build/PhysicalLockscreenGlyphsProduction30pt/Cyanide.app/embedded.mobileprovision}"
ENTITLEMENTS="${CYANIDE_ENTITLEMENTS:-$REPO_ROOT/build/PhysicalLiveGlyph.entitlements}"
LATEST_ARTIFACT_FILE="$REPO_ROOT/build/DirectDeviceUpdate-latest.txt"

usage() {
    cat <<'EOF'
Usage: ./scripts/build-device.sh

Builds the current working tree for arm64 and arm64e, embeds the configured
provisioning profile, and signs a fresh .app for direct physical-device install.
On success, it records the artifact for ./scripts/install-device.sh.

Optional environment overrides:
  CYANIDE_BUNDLE_ID
  CYANIDE_SIGNING_IDENTITY
  CYANIDE_PROFILE
  CYANIDE_ENTITLEMENTS
  CYANIDE_CONFIGURATION
  CYANIDE_PROJECT
  CYANIDE_SCHEME
EOF
}

fail() {
    echo "error: $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_file() {
    [ -f "$1" ] || fail "required file not found: $1"
}

require_architectures() {
    local binary="$1"
    local architectures
    architectures="$(xcrun lipo -archs "$binary")"
    case " $architectures " in
        *" arm64 "*) ;;
        *) fail "$binary is missing its arm64 slice ($architectures)" ;;
    esac
    case " $architectures " in
        *" arm64e "*) ;;
        *) fail "$binary is missing its arm64e slice ($architectures)" ;;
    esac
}

if [ "$#" -gt 0 ]; then
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            fail "unknown argument: $1"
            ;;
    esac
fi

for command_name in xcodebuild xcrun security codesign ditto otool; do
    require_command "$command_name"
done
require_file "$PROFILE"
require_file "$ENTITLEMENTS"

echo "==> checking signing identity and inputs"
security find-identity -v -p codesigning \
    | grep -F "$IDENTITY" >/dev/null \
    || fail "signing identity is unavailable or invalid: $IDENTITY"
security cms -D -i "$PROFILE" >/dev/null 2>&1 \
    || fail "provisioning profile could not be decoded: $PROFILE"

mkdir -p "$REPO_ROOT/build"
STAMP="$(date +%Y%m%d-%H%M%S)"
UPDATE_DIR="$REPO_ROOT/build/DirectDeviceUpdate-$STAMP"
SUFFIX=1
while [ -e "$UPDATE_DIR" ]; do
    UPDATE_DIR="$REPO_ROOT/build/DirectDeviceUpdate-$STAMP-$(printf '%02d' "$SUFFIX")"
    SUFFIX=$((SUFFIX + 1))
done
mkdir "$UPDATE_DIR"

DERIVED_DATA="$UPDATE_DIR/DerivedData"
BUILT_APP="$DERIVED_DATA/Build/Products/$CONFIGURATION-iphoneos/Cyanide.app"
APP="$UPDATE_DIR/Cyanide.app"
BUILD_LOG="$UPDATE_DIR/xcodebuild.log"

echo "==> building the current working tree"
echo "    output: $UPDATE_DIR"
xcodebuild \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -configuration "$CONFIGURATION" \
    -sdk iphoneos \
    -destination 'generic/platform=iOS' \
    -derivedDataPath "$DERIVED_DATA" \
    ARCHS='arm64 arm64e' \
    ONLY_ACTIVE_ARCH=NO \
    CODE_SIGNING_ALLOWED=NO \
    build 2>&1 | tee "$BUILD_LOG"

[ -d "$BUILT_APP" ] || fail "built app not found: $BUILT_APP"
ditto "$BUILT_APP" "$APP"
cp "$PROFILE" "$APP/embedded.mobileprovision"
cmp -s "$PROFILE" "$APP/embedded.mobileprovision" \
    || fail "embedded provisioning profile did not copy exactly"

APP_IDENTIFIER="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Info.plist" 2>/dev/null || true)"
[ "$APP_IDENTIFIER" = "$BUNDLE_ID" ] \
    || fail "built bundle identifier is $APP_IDENTIFIER, expected $BUNDLE_ID"
APP_EXECUTABLE_NAME="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Info.plist" 2>/dev/null || true)"
[ -n "$APP_EXECUTABLE_NAME" ] || fail "built app has no CFBundleExecutable"
APP_EXECUTABLE="$APP/$APP_EXECUTABLE_NAME"
XPF_DYLIB="$APP/libxpf.dylib"
require_file "$APP_EXECUTABLE"
require_file "$XPF_DYLIB"
require_architectures "$APP_EXECUTABLE"
require_architectures "$XPF_DYLIB"

# This is not the Sideloadly compatibility pre-sign used by scripts/build.sh.
# Cyanide currently links @loader_path/libxpf.dylib, so iOS requires the
# embedded dylib to carry a valid development signature before the containing
# app is signed.
otool -L "$APP_EXECUTABLE" | grep -F '@loader_path/libxpf.dylib' >/dev/null \
    || fail "Cyanide no longer links the embedded libxpf.dylib; update this signing contract"

echo "==> signing embedded libxpf.dylib and Cyanide.app"
codesign --force --sign "$IDENTITY" --timestamp=none "$XPF_DYLIB"
codesign --force --sign "$IDENTITY" --timestamp=none \
    --entitlements "$ENTITLEMENTS" --generate-entitlement-der "$APP"

echo "==> verifying signatures"
codesign --verify --strict --verbose=2 "$XPF_DYLIB"
codesign --verify --deep --strict --verbose=2 "$APP"

# Only publish a build after every build, signing, and verification step has
# succeeded. The installer reads this marker instead of guessing from mtimes.
LATEST_ARTIFACT_TMP="$(mktemp "$REPO_ROOT/build/.DirectDeviceUpdate-latest.XXXXXX")"
printf '%s\n' "$APP" > "$LATEST_ARTIFACT_TMP"
mv "$LATEST_ARTIFACT_TMP" "$LATEST_ARTIFACT_FILE"

APP_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Info.plist" 2>/dev/null || true)"
APP_BUILD="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP/Info.plist" 2>/dev/null || true)"
echo
echo "Built and signed Cyanide $APP_VERSION ($APP_BUILD)."
echo "Artifact: $APP"
echo "Run ./scripts/install-device.sh to install this build."
