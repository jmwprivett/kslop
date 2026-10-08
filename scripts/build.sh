#!/usr/bin/env bash
# Build Cyanide for iphoneos and package the resulting .app into a versioned IPA
# under build/, e.g. build/Cyanide-1.0.14.ipa, with a build/Cyanide.ipa
# symlink pointing at the latest build. With SDK=iphonesimulator, build the
# simulator .app and skip IPA packaging.
#
# Run as: ./scripts/build.sh
# Override defaults with env vars:
#   SCHEME, CONFIG (Debug|Release), SDK (iphoneos|iphonesimulator)
#
# The version comes from CFBundleShortVersionString in the built Info.plist
# (= the MARKETING_VERSION build setting in the xcodeproj). Bump
# MARKETING_VERSION to ship a new version.
#
# Code signing is disabled — the IPA ships unsigned for sideload via
# AltStore / TrollStore / Sideloadly, which do their own signing.

set -euo pipefail

cd "$(dirname "$0")/.."

SCHEME="${SCHEME:-Cyanide}"
CONFIG="${CONFIG:-Debug}"
SDK="${SDK:-iphoneos}"
PROJECT="Cyanide.xcodeproj"
DERIVED="$PWD/build/DerivedData"
PRODUCT_DIR="$DERIVED/Build/Products/${CONFIG}-${SDK}"
APP_NAME="Cyanide.app"
IPA_LATEST="$PWD/build/Cyanide.ipa"
XCODEBUILD_EXTRA=()

if [ "$SDK" = "iphonesimulator" ]; then
    XCODEBUILD_EXTRA=(ARCHS=arm64 ONLY_ACTIVE_ARCH=YES)
fi

mkdir -p build

echo "==> xcodebuild ($SCHEME / $CONFIG / $SDK)"
xcodebuild \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -sdk "$SDK" \
    -configuration "$CONFIG" \
    -derivedDataPath "$DERIVED" \
    CODE_SIGNING_ALLOWED=NO \
    ${XCODEBUILD_EXTRA[@]+"${XCODEBUILD_EXTRA[@]}"} \
    build \
    | xcbeautify --quiet 2>/dev/null \
    || xcodebuild \
         -project "$PROJECT" \
         -scheme "$SCHEME" \
         -sdk "$SDK" \
         -configuration "$CONFIG" \
         -derivedDataPath "$DERIVED" \
         CODE_SIGNING_ALLOWED=NO \
         ${XCODEBUILD_EXTRA[@]+"${XCODEBUILD_EXTRA[@]}"} \
         build

APP_PATH="$PRODUCT_DIR/$APP_NAME"
if [ ! -d "$APP_PATH" ]; then
    echo "error: $APP_PATH not found after build" >&2
    exit 1
fi

if [ "$SDK" = "iphonesimulator" ]; then
    echo "==> simulator app $APP_PATH"
    exit 0
fi

# Sideloadly can replace an existing Mach-O signature, but its signer fails
# with error -18 when the embedded fat XPF dylib has no LC_CODE_SIGNATURE at
# all. The XPF Makefile normally applies an ldid signature; an up-to-date or
# externally regenerated artifact can bypass that recipe, and unsigned Xcode
# builds do not repair it. Always give the final embedded dylib a valid ad-hoc
# signature immediately before packaging, then verify both required slices.
XPF_DYLIB_PATH="$APP_PATH/libxpf.dylib"
if [ ! -f "$XPF_DYLIB_PATH" ]; then
    echo "error: $XPF_DYLIB_PATH not found after build" >&2
    exit 1
fi

XPF_ARCHS="$(xcrun lipo -archs "$XPF_DYLIB_PATH")"
case " $XPF_ARCHS " in
    *" arm64 "*) ;;
    *)
        echo "error: libxpf.dylib is missing its arm64 slice ($XPF_ARCHS)" >&2
        exit 1
        ;;
esac
case " $XPF_ARCHS " in
    *" arm64e "*) ;;
    *)
        echo "error: libxpf.dylib is missing its arm64e slice ($XPF_ARCHS)" >&2
        exit 1
        ;;
esac

echo "==> pre-signing embedded libxpf.dylib for sideload signer compatibility"
/usr/bin/codesign --force --sign - --timestamp=none "$XPF_DYLIB_PATH"
/usr/bin/codesign --verify --strict "$XPF_DYLIB_PATH"
for XPF_ARCH in arm64 arm64e; do
    if ! xcrun otool -arch "$XPF_ARCH" -l "$XPF_DYLIB_PATH" \
        | grep -q "LC_CODE_SIGNATURE"; then
        echo "error: libxpf.dylib $XPF_ARCH slice has no LC_CODE_SIGNATURE" >&2
        exit 1
    fi
done

VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$APP_PATH/Info.plist" 2>/dev/null || true)
if [ -z "$VERSION" ]; then
    echo "error: could not read CFBundleShortVersionString from $APP_PATH/Info.plist" >&2
    exit 1
fi

IPA_OUT="$PWD/build/Cyanide-${VERSION}.ipa"
IPA_BASENAME="$(basename "$IPA_OUT")"
LATEST_BASENAME="$(basename "$IPA_LATEST")"

echo "==> packaging $IPA_OUT (version $VERSION)"
STAGE="$(mktemp -d -t cyanide-ipa)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/Payload"
cp -R "$APP_PATH" "$STAGE/Payload/"
rm -f "$IPA_OUT"
(
    cd "$STAGE"

    # Sideloadly 0.70 incorrectly hashes the compressed ZIP representation of
    # each bundle Info.plist into CodeDirectory slot -1. Store every
    # Info.plist verbatim (ZIP method 0) so those bytes equal the extracted
    # plist bytes that installd verifies. Keep ordinary payload files
    # compressed so the workaround does not unnecessarily inflate the IPA.
    zip -qry "$IPA_OUT" Payload -x '*/Info.plist'
    INFO_PLIST_ENTRIES=()
    while IFS= read -r -d '' INFO_PLIST_ENTRY; do
        INFO_PLIST_ENTRIES+=("$INFO_PLIST_ENTRY")
    done < <(find Payload -type f -name Info.plist -print0)
    if [ "${#INFO_PLIST_ENTRIES[@]}" -eq 0 ]; then
        echo "error: no Info.plist entries found while packaging" >&2
        exit 1
    fi
    zip -0 -q "$IPA_OUT" "${INFO_PLIST_ENTRIES[@]}"
)

python3 - "$IPA_OUT" <<'PY'
import sys
import zipfile

ipa = sys.argv[1]
with zipfile.ZipFile(ipa) as archive:
    plists = [entry for entry in archive.infolist()
              if entry.filename.endswith("/Info.plist")]
    compressed = [entry.filename for entry in plists
                  if entry.compress_type != zipfile.ZIP_STORED]
if not plists:
    raise SystemExit("error: packaged IPA contains no Info.plist")
if compressed:
    raise SystemExit(
        "error: compressed Info.plist entries remain: " +
        ", ".join(compressed))
PY

# Keep an unversioned symlink so tooling / README references that expect the
# legacy path still resolve to the latest build.
rm -f "$IPA_LATEST"
( cd "$PWD/build" && ln -s "$IPA_BASENAME" "$LATEST_BASENAME" )

SIZE=$(du -h "$IPA_OUT" | cut -f1)
echo "==> wrote $IPA_OUT ($SIZE)"
echo "==> symlink $IPA_LATEST -> $IPA_BASENAME"
