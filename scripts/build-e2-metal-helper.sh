#!/usr/bin/env bash
# Build and sign the disposable E2 Metal actor as an independent iOS app.

set -euo pipefail

cd "$(dirname "$0")/.."

REPO_ROOT="$PWD"
IDENTITY="${CYANIDE_SIGNING_IDENTITY:-AD6C2216FF76B8581482BC09A86B07F76BAB84CC}"
PROFILE="${CYANIDE_HELPER_PROFILE:-${CYANIDE_PROFILE:-$REPO_ROOT/build/PhysicalLockscreenGlyphsProduction30pt/Cyanide.app/embedded.mobileprovision}}"
SOURCE="$REPO_ROOT/scripts/lab/cnd_e2_metal_helper.m"
INFO_PLIST="$REPO_ROOT/scripts/lab/CNDE2MetalHelper-Info.plist"
ENTITLEMENTS="${CYANIDE_HELPER_ENTITLEMENTS:-$REPO_ROOT/scripts/lab/CNDE2MetalHelper.entitlements}"
BUNDLE_ID="${CYANIDE_HELPER_BUNDLE_ID:-com.zeroxjf.cyanide.e2metal}"
LATEST_ARTIFACT_FILE="$REPO_ROOT/build/E2MetalHelper-latest.txt"
E4_APP_GROUP="group.com.zeroxjf.cyanide.e4.ztgmy9fa3v"
E4_APPLICATION_IDENTIFIER="ZTGMY9FA3V.$BUNDLE_ID"

fail() {
    echo "error: $*" >&2
    exit 1
}

for command_name in xcrun security codesign plutil; do
    command -v "$command_name" >/dev/null 2>&1 \
        || fail "required command not found: $command_name"
done
for required in "$PROFILE" "$SOURCE" "$INFO_PLIST" "$ENTITLEMENTS"; do
    [ -f "$required" ] || fail "required file not found: $required"
done
security find-identity -v -p codesigning \
    | grep -F "$IDENTITY" >/dev/null \
    || fail "signing identity is unavailable or invalid: $IDENTITY"
plutil -lint "$INFO_PLIST" "$ENTITLEMENTS" >/dev/null

PROFILE_PLIST="$(mktemp -t cnd-e2-helper-profile.XXXXXX)"
trap 'rm -f "$PROFILE_PLIST"' EXIT
security cms -D -i "$PROFILE" >"$PROFILE_PLIST" 2>/dev/null \
    || fail "provisioning profile could not be decoded: $PROFILE"

# The E4 route requires a real App Group.  Fail before compiling or publishing
# an artifact unless the requested entitlement and the selected profile both
# authorize the exact same group and non-wildcard helper application ID.
REQUESTED_APP_GROUP="$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.application-groups:0' "$ENTITLEMENTS" 2>/dev/null || true)"
if [ -n "$REQUESTED_APP_GROUP" ]; then
    [ "$REQUESTED_APP_GROUP" = "$E4_APP_GROUP" ] \
        || fail "unsupported helper App Group: $REQUESTED_APP_GROUP"
    REQUESTED_APP_IDENTIFIER="$(/usr/libexec/PlistBuddy -c 'Print :application-identifier' "$ENTITLEMENTS" 2>/dev/null || true)"
    [ "$REQUESTED_APP_IDENTIFIER" = "$E4_APPLICATION_IDENTIFIER" ] \
        || fail "E4 helper entitlements require application-identifier $E4_APPLICATION_IDENTIFIER"
    PROFILE_APP_IDENTIFIER="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:application-identifier' "$PROFILE_PLIST" 2>/dev/null || true)"
    [ "$PROFILE_APP_IDENTIFIER" = "$E4_APPLICATION_IDENTIFIER" ] \
        || fail "E4 helper profile must authorize exact application-identifier $E4_APPLICATION_IDENTIFIER (got ${PROFILE_APP_IDENTIFIER:-missing})"
    PROFILE_GROUPS="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.security.application-groups' "$PROFILE_PLIST" 2>/dev/null || true)"
    printf '%s\n' "$PROFILE_GROUPS" | grep -F "$E4_APP_GROUP" >/dev/null \
        || fail "E4 helper profile does not authorize App Group $E4_APP_GROUP"
    echo "==> verified exact E4 helper App Group provisioning"
fi

mkdir -p "$REPO_ROOT/build"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUTPUT_DIR="$REPO_ROOT/build/E2MetalHelper-$STAMP"
SUFFIX=1
while [ -e "$OUTPUT_DIR" ]; do
    OUTPUT_DIR="$REPO_ROOT/build/E2MetalHelper-$STAMP-$(printf '%02d' "$SUFFIX")"
    SUFFIX=$((SUFFIX + 1))
done
APP="$OUTPUT_DIR/CNDE2MetalHelper.app"
mkdir -p "$APP"
cp "$INFO_PLIST" "$APP/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $BUNDLE_ID" \
    "$APP/Info.plist"
cp "$PROFILE" "$APP/embedded.mobileprovision"

SDK_PATH="$(xcrun --sdk iphoneos --show-sdk-path)"
echo "==> building independent E2 Metal helper"
echo "    output: $OUTPUT_DIR"
xcrun --sdk iphoneos clang \
    -arch arm64 -arch arm64e \
    -isysroot "$SDK_PATH" \
    -miphoneos-version-min=17.0 \
    -mbranch-protection=bti \
    -fobjc-arc -fmodules \
    -framework Foundation -framework UIKit -framework Metal -framework IOKit \
    -Wl,-dead_strip \
    -o "$APP/CNDE2MetalHelper" \
    "$SOURCE"

ARCHITECTURES="$(xcrun lipo -archs "$APP/CNDE2MetalHelper")"
case " $ARCHITECTURES " in *" arm64 "*) ;; *) fail "helper lacks arm64";; esac
case " $ARCHITECTURES " in *" arm64e "*) ;; *) fail "helper lacks arm64e";; esac

codesign --force --sign "$IDENTITY" --timestamp=none \
    --entitlements "$ENTITLEMENTS" --generate-entitlement-der "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

LATEST_TMP="$(mktemp "$REPO_ROOT/build/.E2MetalHelper-latest.XXXXXX")"
printf '%s\n' "$APP" > "$LATEST_TMP"
mv "$LATEST_TMP" "$LATEST_ARTIFACT_FILE"

echo
echo "Built and signed E2 Metal helper."
echo "Artifact: $APP"
