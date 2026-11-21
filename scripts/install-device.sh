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
re-sign, package, uninstall, or launch the replacement app. If an installed Cyanide is
running, the installer first asks that exact process to prove and arm a
recoverable KRW handoff. It terminates the process only after that proof, then
copies and validates the matching termination disposition before the in-place
install. It does not cold-launch or post-launch the replacement.

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

coredevice_app_installed() {
    xcrun devicectl device info apps \
        --device "$DEVICE_ID" --bundle-id "$BUNDLE_ID" \
        --json-output "$APPS_JSON" --timeout 30 >/dev/null
    python3 - "$APPS_JSON" "$BUNDLE_ID" <<'PY'
import json
from pathlib import Path
import sys

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
apps = payload.get("result", {}).get("apps", [])
print(1 if any(
    isinstance(app, dict) and app.get("bundleIdentifier") == sys.argv[2]
    for app in apps
) else 0)
PY
}

coredevice_cyanide_pids() {
    xcrun devicectl device info processes \
        --device "$DEVICE_ID" --json-output "$PROCESSES_JSON" \
        --timeout 30 >/dev/null
    python3 - "$PROCESSES_JSON" <<'PY'
import json
from pathlib import Path
import sys
from urllib.parse import unquote, urlparse

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
processes = payload.get("result", {}).get("runningProcesses", [])
for process in processes:
    if not isinstance(process, dict):
        continue
    executable = process.get("executable")
    pid = process.get("processIdentifier")
    if not isinstance(executable, str) or type(pid) is not int:
        continue
    path = unquote(urlparse(executable).path)
    if path.endswith("/Cyanide.app/Cyanide"):
        print(pid)
PY
}

cyanide_pid_count() {
    printf '%s\n' "$1" | awk 'NF {count++} END {print count+0}'
}

terminate_cyanide_pid() {
    local pid="$1"
    echo "==> gracefully terminating Cyanide pid $pid"
    xcrun devicectl device process terminate \
        --device "$DEVICE_ID" --pid "$pid" --timeout 45
    local remaining="$pid"
    local attempt
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        remaining="$(coredevice_cyanide_pids)"
        [ -z "$remaining" ] && break
        sleep 1
    done
    [ -z "$remaining" ] \
        || fail "Cyanide did not exit after normal termination (pid $remaining)"
}

prepare_cyanide_update_handoff() {
    local pid="$1"
    local result_json="$2"
    echo "==> proving recoverable KRW update handoff in Cyanide pid $pid"
    python3 "$REPO_ROOT/scripts/lab/cnd_live_probe.py" \
        krw-update-handoff --device "$DEVICE_ID" --timeout 90 \
        --json-output "$result_json"

    IFS=$'\t' read -r HANDOFF_REQUEST_ID HANDOFF_GENERATION_ID \
        HANDOFF_SERIAL HANDOFF_PID < <(python3 - "$result_json" <<'PY'
import json
from pathlib import Path
import sys

result = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
values = (
    result.get("requestID"),
    result.get("generationID"),
    result.get("handoffSerial"),
    result.get("pid"),
)
if not isinstance(values[0], str) or not values[0]:
    raise SystemExit("update handoff result has no request ID")
if not isinstance(values[1], str) or not values[1]:
    raise SystemExit("update handoff result has no generation ID")
if type(values[2]) is not int or values[2] <= 0:
    raise SystemExit("update handoff result has no positive serial")
if type(values[3]) is not int or values[3] <= 0:
    raise SystemExit("update handoff result has no process ID")
print(*values, sep="\t")
PY
    )
    [ "$HANDOFF_PID" = "$pid" ] \
        || fail "handoff was proved by pid $HANDOFF_PID, expected live pid $pid"
}

copy_and_validate_termination() {
    local destination="$1"
    echo "==> validating exact post-exit KRW disposition"
    xcrun devicectl device copy from \
        --device "$DEVICE_ID" \
        --source "Documents/cnd-termination.json" \
        --destination "$destination" \
        --domain-type appDataContainer \
        --domain-identifier "$BUNDLE_ID" \
        --timeout 30 >/dev/null
    require_file "$destination"
    python3 - "$destination" "$HANDOFF_REQUEST_ID" \
        "$HANDOFF_GENERATION_ID" "$HANDOFF_SERIAL" "$HANDOFF_PID" <<'PY'
import json
from pathlib import Path
import sys

path, request_id, generation_id, serial_text, pid_text = sys.argv[1:]
record = json.loads(Path(path).read_text(encoding="utf-8"))
expected = {
    "reason": "SIGTERM",
    "disposition": "recoverable-anchored",
    "handoffRequestID": request_id,
    "generationID": generation_id,
    "handoffSerial": int(serial_text),
    "pid": int(pid_text),
    "nextProcessArmed": True,
}
mismatches = [
    f"{key}={record.get(key)!r} expected {value!r}"
    for key, value in expected.items()
    if record.get(key) != value
]
if mismatches:
    raise SystemExit(
        "post-exit KRW disposition did not match the armed handoff: "
        + "; ".join(mismatches)
    )
PY
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
ARTIFACT_DIR="$(dirname "$APP")"
INSTALL_STAMP="$(date +%Y%m%d-%H%M%S)"
HANDOFF_RESULT_JSON="$ARTIFACT_DIR/update-handoff-$INSTALL_STAMP.json"
HANDOFF_TERMINATION_JSON="$ARTIFACT_DIR/termination-$INSTALL_STAMP.json"
HANDOFF_REQUEST_ID=""
HANDOFF_GENERATION_ID=""
HANDOFF_SERIAL=""
HANDOFF_PID=""

for command_name in xcrun codesign otool security python3; do
    require_command "$command_name"
done
APPS_JSON="$(mktemp "${TMPDIR:-/tmp}/cyanide-apps.XXXXXX")"
PROCESSES_JSON="$(mktemp "${TMPDIR:-/tmp}/cyanide-processes.XXXXXX")"
DEVICES_JSON="$(mktemp "${TMPDIR:-/tmp}/cyanide-devices.XXXXXX")"
trap 'rm -f "$APPS_JSON" "$PROCESSES_JSON" "$DEVICES_JSON"' EXIT
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
SPRINGBOARD_PROBE_DYLIB="$APP/CNDSpringBoardDylibProbe.dylib"
require_file "$APP_EXECUTABLE"
require_file "$XPF_DYLIB"
require_file "$SPRINGBOARD_PROBE_DYLIB"
require_architectures "$APP_EXECUTABLE"
require_architectures "$XPF_DYLIB"
require_architectures "$SPRINGBOARD_PROBE_DYLIB"
otool -L "$APP_EXECUTABLE" | grep -F '@loader_path/libxpf.dylib' >/dev/null \
    || fail "Cyanide does not link its embedded libxpf.dylib"
security cms -D -i "$APP/embedded.mobileprovision" >/dev/null 2>&1 \
    || fail "embedded provisioning profile could not be decoded"
cmp -s "$PROFILE" "$APP/embedded.mobileprovision" \
    || fail "artifact does not contain the configured provisioning profile"
codesign --verify --strict --verbose=2 "$XPF_DYLIB"
codesign --verify --strict --verbose=2 "$SPRINGBOARD_PROBE_DYLIB"
codesign --verify --deep --strict --verbose=2 "$APP"

echo "==> checking paired device $DEVICE_NAME ($DEVICE_ID)"
# Decide on the versioned JSON output, not the human table: the table's state
# strings are not a stable interface, and "unavailable (paired)" would satisfy
# a substring match for "available (paired)".
xcrun devicectl list devices --json-output "$DEVICES_JSON" --timeout 30 >/dev/null
DEVICE_TUNNEL="$(python3 - "$DEVICES_JSON" "$DEVICE_ID" <<'PY'
import json
from pathlib import Path
import sys

devices = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("result", {}).get("devices", [])
for device in devices:
    if isinstance(device, dict) and device.get("identifier") == sys.argv[2]:
        print(device.get("connectionProperties", {}).get("tunnelState", "unknown"))
        break
PY
)"
[ -n "$DEVICE_TUNNEL" ] || fail "CoreDevice ID $DEVICE_ID is not present"
[ "$DEVICE_TUNNEL" != "unavailable" ] \
    || fail "$DEVICE_NAME ($DEVICE_ID) is paired but not reachable (tunnelState: unavailable); connect it over USB or enable network debugging"
# The tunnel state alone does not prove this is the pinned target; require the
# detailed record to match the same ID, name, and paired state.
DEVICE_DETAILS="$(xcrun devicectl device info details \
    --device "$DEVICE_ID" --timeout 30)" \
    || fail "could not query device $DEVICE_NAME ($DEVICE_ID) (tunnelState: $DEVICE_TUNNEL)"
printf '%s\n' "$DEVICE_DETAILS" | grep -F "identifier: $DEVICE_ID" >/dev/null \
    || fail "connected device details do not match CoreDevice ID $DEVICE_ID"
printf '%s\n' "$DEVICE_DETAILS" | grep -F "name: $DEVICE_NAME" >/dev/null \
    || fail "connected device details do not match name $DEVICE_NAME"
printf '%s\n' "$DEVICE_DETAILS" | grep -F "pairingState: paired" >/dev/null \
    || fail "connected device is not paired"

echo "==> checking for an existing Cyanide installation"
CURRENT_APP_INSTALLED="$(coredevice_app_installed)"

echo "==> checking for a running Cyanide process"
CYANIDE_PIDS="$(coredevice_cyanide_pids)"
PID_COUNT="$(cyanide_pid_count "$CYANIDE_PIDS")"
if [ "$PID_COUNT" -gt 1 ]; then
    fail "found multiple Cyanide processes; refusing to guess: $CYANIDE_PIDS"
fi
if [ "$CURRENT_APP_INSTALLED" -eq 0 ] && [ "$PID_COUNT" -ne 0 ]; then
    fail "Cyanide is running but its bundle is not registered; refusing an inconsistent update"
fi
# A running Cyanide must first acknowledge an exact generation/serial handoff
# over the authenticated live channel. Process disappearance alone is never
# accepted as proof: after exit, the installer copies the container record and
# requires the same request, generation, serial, PID, and anchored disposition.
if [ "$PID_COUNT" -ne 0 ]; then
    CYANIDE_PID="$(printf '%s\n' "$CYANIDE_PIDS" | awk 'NF {print; exit}')"
    prepare_cyanide_update_handoff "$CYANIDE_PID" "$HANDOFF_RESULT_JSON"
    terminate_cyanide_pid "$CYANIDE_PID"
    copy_and_validate_termination "$HANDOFF_TERMINATION_JSON"
fi

# This must remain an in-place update of the same bundle identifier. Never add
# a device-uninstall step here: uninstalling deletes the app data container
# that owns the durable KRW recovery record. launchd owns the parked fileports;
# the preserved container supplies their names, tokens, and restore snapshot to
# the replacement app process.
echo "==> installing in place on $DEVICE_NAME (preserving app data and parked KRW record)"
INSTALL_LOG="$ARTIFACT_DIR/install-$INSTALL_STAMP.log"
xcrun devicectl device install app \
    --device "$DEVICE_ID" "$APP" --timeout 120 2>&1 | tee "$INSTALL_LOG"

echo "==> verifying device registration"
REGISTRATION_LOG="$ARTIFACT_DIR/registration-$INSTALL_STAMP.log"
xcrun devicectl device info apps \
    --device "$DEVICE_ID" --bundle-id "$BUNDLE_ID" \
    --json-output "$APPS_JSON" --timeout 30 2>&1 | tee "$REGISTRATION_LOG"
[ "$(coredevice_app_installed)" -eq 1 ] \
    || fail "CoreDevice did not report the installed bundle $BUNDLE_ID"

APP_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Info.plist" 2>/dev/null || true)"
APP_BUILD="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP/Info.plist" 2>/dev/null || true)"
echo
echo "Installed Cyanide $APP_VERSION ($APP_BUILD) on $DEVICE_NAME."
echo "Artifact: $APP"
echo "The app was not launched."
