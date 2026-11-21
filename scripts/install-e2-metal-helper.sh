#!/usr/bin/env bash
# Validate and install the latest independently signed E2 Metal helper.

set -euo pipefail

cd "$(dirname "$0")/.."

REPO_ROOT="$PWD"
DEVICE_ID="${CYANIDE_DEVICE_ID:-828515D1-88C1-5CEB-A16F-5AD0AE3E3641}"
BUNDLE_ID="${CYANIDE_HELPER_BUNDLE_ID:-com.zeroxjf.cyanide.e2metal}"
LATEST_ARTIFACT_FILE="$REPO_ROOT/build/E2MetalHelper-latest.txt"

fail() {
    echo "error: $*" >&2
    exit 1
}

[ -f "$LATEST_ARTIFACT_FILE" ] || fail "no verified helper artifact marker"
APP="$(sed -n '1p' "$LATEST_ARTIFACT_FILE")"
case "$APP" in
    "$REPO_ROOT"/build/E2MetalHelper-*/CNDE2MetalHelper.app) ;;
    *) fail "helper artifact marker points outside the expected build path: $APP" ;;
esac
[ -d "$APP" ] || fail "helper artifact does not exist: $APP"
codesign --verify --deep --strict --verbose=2 "$APP"
IDENTIFIER="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Info.plist")"
[ "$IDENTIFIER" = "$BUNDLE_ID" ] \
    || fail "helper bundle identifier is $IDENTIFIER, expected $BUNDLE_ID"
ARCHITECTURES="$(xcrun lipo -archs "$APP/CNDE2MetalHelper")"
case " $ARCHITECTURES " in *" arm64 "*) ;; *) fail "helper lacks arm64";; esac
case " $ARCHITECTURES " in *" arm64e "*) ;; *) fail "helper lacks arm64e";; esac

DEVICES="$(xcrun devicectl list devices)"
printf '%s\n' "$DEVICES" | grep -F "$DEVICE_ID" | grep -E 'available|connected' >/dev/null \
    || fail "target device is not available: $DEVICE_ID"

PROCESSES="$(xcrun devicectl device info processes \
    --device "$DEVICE_ID" --columns '*' --timeout 30)"
if printf '%s\n' "$PROCESSES" | grep -F '/CNDE2MetalHelper.app/CNDE2MetalHelper' >/dev/null; then
    fail "an E2 helper process is already running; refusing to replace it"
fi

echo "==> installing independent E2 Metal helper"
xcrun devicectl device install app --device "$DEVICE_ID" "$APP"
echo "==> verifying helper registration"
xcrun devicectl device info apps --device "$DEVICE_ID" \
    --bundle-id "$BUNDLE_ID" --columns '*'

echo
echo "Installed E2 Metal helper on $DEVICE_ID."
echo "Artifact: $APP"
