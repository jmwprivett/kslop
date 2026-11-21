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
SPRINGBOARD_PROBE_SOURCE="$REPO_ROOT/scripts/lab/cnd_springboard_dylib_probe.c"
SPRINGBOARD_PROBE_NAME="CNDSpringBoardDylibProbe.dylib"
E4_APP_GROUP="group.com.zeroxjf.cyanide.e4.ztgmy9fa3v"
E4_APPLICATION_IDENTIFIER="ZTGMY9FA3V.$BUNDLE_ID"

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
require_file "$SPRINGBOARD_PROBE_SOURCE"

echo "==> checking signing identity and inputs"
security find-identity -v -p codesigning \
    | grep -F "$IDENTITY" >/dev/null \
    || fail "signing identity is unavailable or invalid: $IDENTITY"
plutil -lint "$ENTITLEMENTS" >/dev/null \
    || fail "entitlements are not a valid property list: $ENTITLEMENTS"

PROFILE_PLIST="$(mktemp -t cnd-device-profile.XXXXXX)"
trap 'rm -f "$PROFILE_PLIST"' EXIT
security cms -D -i "$PROFILE" >"$PROFILE_PLIST" 2>/dev/null \
    || fail "provisioning profile could not be decoded: $PROFILE"

# App Group builds must use an explicit profile for this exact application.
# A wildcard profile can sign ordinary Cyanide builds, but cannot authorize
# this route's shared container and must never publish an E4 artifact.
REQUESTED_APP_GROUP="$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.application-groups:0' "$ENTITLEMENTS" 2>/dev/null || true)"
if [ -n "$REQUESTED_APP_GROUP" ]; then
    [ "$REQUESTED_APP_GROUP" = "$E4_APP_GROUP" ] \
        || fail "unsupported Cyanide App Group: $REQUESTED_APP_GROUP"
    REQUESTED_APP_IDENTIFIER="$(/usr/libexec/PlistBuddy -c 'Print :application-identifier' "$ENTITLEMENTS" 2>/dev/null || true)"
    [ "$REQUESTED_APP_IDENTIFIER" = "$E4_APPLICATION_IDENTIFIER" ] \
        || fail "E4 Cyanide entitlements require application-identifier $E4_APPLICATION_IDENTIFIER"
    PROFILE_APP_IDENTIFIER="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:application-identifier' "$PROFILE_PLIST" 2>/dev/null || true)"
    [ "$PROFILE_APP_IDENTIFIER" = "$E4_APPLICATION_IDENTIFIER" ] \
        || fail "E4 Cyanide profile must authorize exact application-identifier $E4_APPLICATION_IDENTIFIER (got ${PROFILE_APP_IDENTIFIER:-missing})"
    PROFILE_GROUPS="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.security.application-groups' "$PROFILE_PLIST" 2>/dev/null || true)"
    printf '%s\n' "$PROFILE_GROUPS" | grep -F "$E4_APP_GROUP" >/dev/null \
        || fail "E4 Cyanide profile does not authorize App Group $E4_APP_GROUP"
    echo "==> verified exact E4 Cyanide App Group provisioning"
fi

mkdir -p "$REPO_ROOT/build"
STAMP="$(date +%Y%m%d-%H%M%S)"
UPDATE_DIR="$REPO_ROOT/build/DirectDeviceUpdate-$STAMP"
SUFFIX=1
while [ -e "$UPDATE_DIR" ]; do
    UPDATE_DIR="$REPO_ROOT/build/DirectDeviceUpdate-$STAMP-$(printf '%02d' "$SUFFIX")"
    SUFFIX=$((SUFFIX + 1))
done
mkdir "$UPDATE_DIR"

# Keep exactly one device build on disk. A failed build removes its own partial
# output so the previously published artifact stays installable; a successful
# build replaces every older DirectDeviceUpdate-* directory (see below).
BUILD_PUBLISHED=0
cleanup() {
    rm -f "$PROFILE_PLIST"
    if [ "$BUILD_PUBLISHED" -ne 1 ] && [ -n "${UPDATE_DIR:-}" ]; then
        rm -rf "$UPDATE_DIR"
    fi
}
trap cleanup EXIT

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
    PRODUCT_BUNDLE_IDENTIFIER="$BUNDLE_ID" \
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
SPRINGBOARD_PROBE_DYLIB="$APP/$SPRINGBOARD_PROBE_NAME"
require_file "$APP_EXECUTABLE"
require_file "$XPF_DYLIB"
require_architectures "$APP_EXECUTABLE"
require_architectures "$XPF_DYLIB"

echo "==> building inert SpringBoard dylib boundary probe"
xcrun --sdk iphoneos clang \
    -arch arm64 -arch arm64e \
    -isysroot "$(xcrun --sdk iphoneos --show-sdk-path)" \
    -miphoneos-version-min=17.0 \
    -mbranch-protection=bti \
    -dynamiclib -fvisibility=hidden \
    -Wl,-install_name,"@rpath/$SPRINGBOARD_PROBE_NAME" \
    -o "$SPRINGBOARD_PROBE_DYLIB" \
    "$SPRINGBOARD_PROBE_SOURCE"
require_file "$SPRINGBOARD_PROBE_DYLIB"
require_architectures "$SPRINGBOARD_PROBE_DYLIB"

# This is not the Sideloadly compatibility pre-sign used by scripts/build.sh.
# Cyanide currently links @loader_path/libxpf.dylib, so iOS requires the
# embedded dylib to carry a valid development signature before the containing
# app is signed.
otool -L "$APP_EXECUTABLE" | grep -F '@loader_path/libxpf.dylib' >/dev/null \
    || fail "Cyanide no longer links the embedded libxpf.dylib; update this signing contract"

echo "==> signing embedded dylibs and Cyanide.app"
codesign --force --sign "$IDENTITY" --timestamp=none "$XPF_DYLIB"
codesign --force --sign "$IDENTITY" --timestamp=none \
    "$SPRINGBOARD_PROBE_DYLIB"
codesign --force --sign "$IDENTITY" --timestamp=none \
    --entitlements "$ENTITLEMENTS" --generate-entitlement-der "$APP"

echo "==> verifying signatures"
codesign --verify --strict --verbose=2 "$XPF_DYLIB"
codesign --verify --strict --verbose=2 "$SPRINGBOARD_PROBE_DYLIB"
codesign --verify --deep --strict --verbose=2 "$APP"

# Only publish a build after every build, signing, and verification step has
# succeeded. The installer reads this marker instead of guessing from mtimes.
LATEST_ARTIFACT_TMP="$(mktemp "$REPO_ROOT/build/.DirectDeviceUpdate-latest.XXXXXX")"
printf '%s\n' "$APP" > "$LATEST_ARTIFACT_TMP"
mv "$LATEST_ARTIFACT_TMP" "$LATEST_ARTIFACT_FILE"
BUILD_PUBLISHED=1

echo "==> replacing previous device builds"
# DerivedData is per-build scratch (~400 MB); only Cyanide.app and the log are
# needed by install-device.sh.
rm -rf "$DERIVED_DATA"
for old_dir in "$REPO_ROOT"/build/DirectDeviceUpdate-*/; do
    old_dir="${old_dir%/}"
    [ "$old_dir" = "$UPDATE_DIR" ] && continue
    rm -rf "$old_dir"
done

APP_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Info.plist" 2>/dev/null || true)"
APP_BUILD="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP/Info.plist" 2>/dev/null || true)"
echo
echo "Built and signed Cyanide $APP_VERSION ($APP_BUILD)."
echo "Artifact: $APP"
echo "Run ./scripts/install-device.sh to install this build."
