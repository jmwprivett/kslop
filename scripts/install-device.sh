#!/usr/bin/env bash
# Validate and directly install the latest successful device build.

set -euo pipefail

cd "$(dirname "$0")/.."

REPO_ROOT="$PWD"
DEVICE_NAME="${CYANIDE_DEVICE_NAME:-iPinky Max}"
DEVICE_ID="${CYANIDE_DEVICE_ID:-828515D1-88C1-5CEB-A16F-5AD0AE3E3641}"
BUNDLE_ID="${CYANIDE_BUNDLE_ID:-com.zeroxjf.ios-cyanide1}"
PROFILE="${CYANIDE_PROFILE:-$REPO_ROOT/build/PhysicalLockscreenGlyphsProduction30pt/Cyanide.app/embedded.mobileprovision}"
LATEST_ARTIFACT_FILE="$REPO_ROOT/build/DirectDeviceUpdate-latest.txt"

usage() {
    cat <<'EOF'
Usage: ./scripts/install-device.sh

Validates and installs the latest successful signed build produced by
./scripts/build-device.sh directly on iPinky Max. It does not build, modify,
re-sign, package, uninstall, or launch the app.

Optional environment overrides:
  CYANIDE_DEVICE_NAME
  CYANIDE_DEVICE_ID
  CYANIDE_BUNDLE_ID
  CYANIDE_PROFILE
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

require_file "$LATEST_ARTIFACT_FILE"
IFS= read -r APP < "$LATEST_ARTIFACT_FILE" \
    || fail "could not read latest build marker: $LATEST_ARTIFACT_FILE"
[ -n "$APP" ] || fail "latest build marker is empty: $LATEST_ARTIFACT_FILE"
case "$APP" in
    "$REPO_ROOT"/build/DirectDeviceUpdate-*/Cyanide.app) ;;
    *) fail "latest build marker contains an unexpected path: $APP" ;;
esac
[ -d "$APP" ] || fail "latest built app is missing; rerun ./scripts/build-device.sh: $APP"

for command_name in xcrun codesign otool security; do
    require_command "$command_name"
done
require_file "$PROFILE"
require_file "$APP/Info.plist"
require_file "$APP/embedded.mobileprovision"

echo "==> validating signed artifact $APP"
APP_IDENTIFIER="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Info.plist" 2>/dev/null || true)"
[ "$APP_IDENTIFIER" = "$BUNDLE_ID" ] \
    || fail "artifact bundle identifier is $APP_IDENTIFIER, expected $BUNDLE_ID"
APP_EXECUTABLE_NAME="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Info.plist" 2>/dev/null || true)"
[ -n "$APP_EXECUTABLE_NAME" ] || fail "artifact has no CFBundleExecutable"
APP_EXECUTABLE="$APP/$APP_EXECUTABLE_NAME"
XPF_DYLIB="$APP/libxpf.dylib"
require_file "$APP_EXECUTABLE"
require_file "$XPF_DYLIB"
require_architectures "$APP_EXECUTABLE"
require_architectures "$XPF_DYLIB"
otool -L "$APP_EXECUTABLE" | grep -F '@loader_path/libxpf.dylib' >/dev/null \
    || fail "Cyanide does not link its embedded libxpf.dylib"
security cms -D -i "$APP/embedded.mobileprovision" >/dev/null 2>&1 \
    || fail "embedded provisioning profile could not be decoded"
cmp -s "$PROFILE" "$APP/embedded.mobileprovision" \
    || fail "artifact does not contain the configured provisioning profile"
codesign --verify --strict --verbose=2 "$XPF_DYLIB"
codesign --verify --deep --strict --verbose=2 "$APP"

echo "==> checking paired device $DEVICE_NAME ($DEVICE_ID)"
DEVICE_LINE="$(xcrun devicectl list devices | grep -F "$DEVICE_ID" || true)"
[ -n "$DEVICE_LINE" ] || fail "CoreDevice ID $DEVICE_ID is not present"
case "$DEVICE_LINE" in
    *"$DEVICE_NAME"*"available (paired)"*) ;;
    *) fail "device is not the expected available paired target: $DEVICE_LINE" ;;
esac

echo "==> checking for a running Cyanide process"
PROCESS_LIST="$(xcrun devicectl device info processes \
    --device "$DEVICE_ID" --columns '*' --timeout 30)"
CYANIDE_PIDS="$(printf '%s\n' "$PROCESS_LIST" \
    | awk '$1 ~ /^[0-9]+$/ && $0 ~ /\/Cyanide\.app\/Cyanide/ {print $1}')"
PID_COUNT="$(printf '%s\n' "$CYANIDE_PIDS" | awk 'NF {count++} END {print count+0}')"
if [ "$PID_COUNT" -gt 1 ]; then
    fail "found multiple Cyanide processes; refusing to guess: $CYANIDE_PIDS"
fi
if [ "$PID_COUNT" -eq 1 ]; then
    CYANIDE_PID="$(printf '%s\n' "$CYANIDE_PIDS" | awk 'NF {print; exit}')"
    echo "==> gracefully terminating Cyanide pid $CYANIDE_PID"
    xcrun devicectl device process terminate \
        --device "$DEVICE_ID" --pid "$CYANIDE_PID" --timeout 30
    REMAINING="$CYANIDE_PID"
    for _attempt in 1 2 3 4 5 6 7 8 9 10; do
        REMAINING="$(xcrun devicectl device info processes \
            --device "$DEVICE_ID" --columns '*' --timeout 30 \
            | awk '$1 ~ /^[0-9]+$/ && $0 ~ /\/Cyanide\.app\/Cyanide/ {print $1}')"
        [ -z "$REMAINING" ] && break
        sleep 1
    done
    [ -z "$REMAINING" ] \
        || fail "Cyanide did not exit after normal termination (pid $REMAINING)"
fi

ARTIFACT_DIR="$(dirname "$APP")"
INSTALL_STAMP="$(date +%Y%m%d-%H%M%S)"
echo "==> installing directly on $DEVICE_NAME"
INSTALL_LOG="$ARTIFACT_DIR/install-$INSTALL_STAMP.log"
xcrun devicectl device install app \
    --device "$DEVICE_ID" "$APP" --timeout 120 2>&1 | tee "$INSTALL_LOG"

echo "==> verifying device registration"
REGISTRATION_LOG="$ARTIFACT_DIR/registration-$INSTALL_STAMP.log"
xcrun devicectl device info apps \
    --device "$DEVICE_ID" --bundle-id "$BUNDLE_ID" \
    --columns '*' --timeout 30 2>&1 | tee "$REGISTRATION_LOG"
grep -F "$BUNDLE_ID" "$REGISTRATION_LOG" >/dev/null \
    || fail "CoreDevice did not report the installed bundle $BUNDLE_ID"

APP_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Info.plist" 2>/dev/null || true)"
APP_BUILD="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP/Info.plist" 2>/dev/null || true)"
echo
echo "Installed Cyanide $APP_VERSION ($APP_BUILD) on $DEVICE_NAME."
echo "Artifact: $APP"
echo "The app was not launched."
