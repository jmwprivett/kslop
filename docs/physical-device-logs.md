# Collect and inspect Cyanide logs from a physical device

This runbook covers the evidence normally needed after a Cyanide operation on
the paired **iPinky Max**: Cyanide session logs, JSON/plist reports, installed
app and process state, iOS crash and kernel-panic reports, unified logs, and a
full sysdiagnose. The copy and inspection commands are read-only with respect
to the device.

## Fixed device information

```sh
cd /path/to/kslop

CND_DEVICE_ID='828515D1-88C1-5CEB-A16F-5AD0AE3E3641'
CND_DEVICE_NAME='iPinky Max'
CND_BUNDLE_ID='com.zeroxjf.ios-cyanide1'
CND_CAPTURE_DIR="$(mktemp -d /tmp/cyanide-physical-logs.XXXXXX)"

echo "$CND_CAPTURE_DIR"
xcrun devicectl list devices | rg -F "$CND_DEVICE_ID"
```

Always use the exact CoreDevice ID. Do not substitute the separate device
whose display name is only `iPhone`.

## Capture current app and process state

Save structured JSON whenever a command supports `--json-output`; Apple treats
that as the stable machine-readable interface.

```sh
xcrun devicectl device info apps \
  --device "$CND_DEVICE_ID" \
  --bundle-id "$CND_BUNDLE_ID" \
  --columns '*' \
  --json-output "$CND_CAPTURE_DIR/apps.json"

xcrun devicectl device info processes \
  --device "$CND_DEVICE_ID" \
  --columns '*' \
  --json-output "$CND_CAPTURE_DIR/processes.json"

xcrun devicectl device info lockState \
  --device "$CND_DEVICE_ID" \
  --json-output "$CND_CAPTURE_DIR/lock-state.json"
```

For a quick human-readable process check:

```sh
xcrun devicectl device info processes \
  --device "$CND_DEVICE_ID" \
  --columns '*' | rg -i 'Cyanide|SpringBoard|Spotlight'
```

## Cyanide session logs and reports

Cyanide's app-data domain is selected by bundle ID, so its changing container
UUID never needs to be discovered or hard-coded.

### Inventory Documents

```sh
xcrun devicectl device info files \
  --device "$CND_DEVICE_ID" \
  --domain-type appDataContainer \
  --domain-identifier "$CND_BUNDLE_ID" \
  --subdirectory Documents \
  --columns '*' \
  --json-output "$CND_CAPTURE_DIR/app-files.json"
```

Print the log/report-like files newest first without parsing the table output:

```sh
python3 - "$CND_CAPTURE_DIR/app-files.json" <<'PY'
import json
import sys

root = json.load(open(sys.argv[1]))
rows = []

def walk(value):
    if isinstance(value, dict):
        if "relativePath" in value:
            path = str(value.get("relativePath", ""))
            if path.endswith((".log", ".json", ".plist")):
                metadata = value.get("metadata", {})
                rows.append((
                    str(metadata.get("lastModDate", "")),
                    int(metadata.get("size", 0)),
                    path,
                ))
        for child in value.values():
            walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)

walk(root)
for modified, size, path in sorted(rows, reverse=True):
    print(f"{modified}\t{size:>10}\t{path}")
PY
```

The primary Cyanide artifacts are:

- `Documents/chain-YYYYMMDD-HHMMSS.log`: timestamped action/session log.
  Cyanide keeps the newest 20 session logs.
- `Documents/CNDHailMaryProbe.json`: latest Hail Mary read-only proof.
- `Documents/CNDHailMaryPatch.json`: latest Hail Mary patch/restore journal.
- Other feature-specific `.json` and `.plist` files shown by the inventory.

### Copy selected Cyanide files

Set the session filename from the inventory above:

```sh
CND_SESSION_LOG='chain-YYYYMMDD-HHMMSS.log'

xcrun devicectl device copy from \
  --device "$CND_DEVICE_ID" \
  --domain-type appDataContainer \
  --domain-identifier "$CND_BUNDLE_ID" \
  --source "Documents/$CND_SESSION_LOG" \
  --destination "$CND_CAPTURE_DIR/$CND_SESSION_LOG"

xcrun devicectl device copy from \
  --device "$CND_DEVICE_ID" \
  --domain-type appDataContainer \
  --domain-identifier "$CND_BUNDLE_ID" \
  --source Documents/CNDHailMaryProbe.json \
  --destination "$CND_CAPTURE_DIR/CNDHailMaryProbe.json"

xcrun devicectl device copy from \
  --device "$CND_DEVICE_ID" \
  --domain-type appDataContainer \
  --domain-identifier "$CND_BUNDLE_ID" \
  --source Documents/CNDHailMaryPatch.json \
  --destination "$CND_CAPTURE_DIR/CNDHailMaryPatch.json"
```

Inspect JSON without dumping unrelated nested data:

```sh
jq '{operation, stage, result, message, startedAtUnixTime,
     kernelWritePrimitiveInvocationCount,
     sharedPhysicalCodeWordMutationCount,
     springBoardPageWire, preflight, write,
     writeDispatchReturned, physicalReadbackPerformed,
     postflightProbePerformed}' \
  "$CND_CAPTURE_DIR/CNDHailMaryPatch.json"
```

To preserve every Cyanide document, copy the complete Documents directory.
This may be large because it can contain themes, backups, exported catalogs,
and multi-megabyte trace reports.

```sh
xcrun devicectl device copy from \
  --device "$CND_DEVICE_ID" \
  --domain-type appDataContainer \
  --domain-identifier "$CND_BUNDLE_ID" \
  --source Documents \
  --destination "$CND_CAPTURE_DIR/Cyanide-Documents"
```

### Session-log caveat after a panic

`chain-*.log` is flushed with stdio after each completed line but is not
`fsync`/`F_FULLFSYNC`-durable. A kernel panic can therefore leave the newest
session file empty or truncated. That does **not** prove the action never ran.
Correlate it with the durable operation journal, its modification time, and
the panic's Cyanide stack. For the Hail Mary mutation specifically, an
`armed-...-no-readback` journal is the checkpoint written before entering the
writer; counters normally remain zero when the panic prevents the call from
returning and the report from being updated.

## iOS crash and kernel-panic reports

### Inventory system crash logs

```sh
xcrun devicectl device info files \
  --device "$CND_DEVICE_ID" \
  --domain-type systemCrashLogs \
  --columns '*' \
  --json-output "$CND_CAPTURE_DIR/crash-files.json"
```

Print `.ips` reports newest first:

```sh
python3 - "$CND_CAPTURE_DIR/crash-files.json" <<'PY'
import json
import sys

root = json.load(open(sys.argv[1]))
rows = []

def walk(value):
    if isinstance(value, dict):
        path = str(value.get("relativePath", ""))
        if path.endswith(".ips"):
            metadata = value.get("metadata", {})
            rows.append((
                str(metadata.get("lastModDate", "")),
                int(metadata.get("size", 0)),
                path,
            ))
        for child in value.values():
            walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)

walk(root)
for modified, size, path in sorted(rows, reverse=True):
    print(f"{modified}\t{size:>10}\t{path}")
PY
```

Files beginning with `panic-full-` are full kernel panics. Other useful files
include `Cyanide-*.ips`, `JetsamEvent-*.ips`, resource-limit reports, and crash
reports for SpringBoard or Spotlight.

### Copy a selected panic or crash report

Set the exact relative path printed by the inventory:

```sh
CND_CRASH_REPORT='panic-full-YYYY-MM-DD-HHMMSS.0002.ips'

xcrun devicectl device copy from \
  --device "$CND_DEVICE_ID" \
  --domain-type systemCrashLogs \
  --source "$CND_CRASH_REPORT" \
  --destination "$CND_CAPTURE_DIR/$CND_CRASH_REPORT"
```

### Read a panic without flooding the terminal

A modern `.ips` panic contains two consecutive JSON objects: a short metadata
record and the full payload. This prints the timestamp and `panicString` only:

```sh
python3 - "$CND_CAPTURE_DIR/$CND_CRASH_REPORT" <<'PY'
import json
import sys

text = open(sys.argv[1]).read()
decoder = json.JSONDecoder()
metadata, offset = decoder.raw_decode(text)
while offset < len(text) and text[offset].isspace():
    offset += 1
payload, _ = decoder.raw_decode(text, offset)

print(json.dumps(metadata, indent=2))
print()
print(payload.get("panicString", "<no panicString>"))
PY
```

For Hail Mary analysis, record these fields before drawing conclusions:

- panic timestamp, OS build, product, boot-session UUID, and kernelcache UUID;
- `Panicked task ... pid ...: Cyanide`;
- `pc`, `far`, `esr`, and registers `x0` through `x4`;
- kernel text-exec base and slide;
- the panicked thread's `userFrames`;
- whether the durable patch journal stopped at its armed checkpoint.

A journal that stops before its post-call update cannot say whether an
in-flight physical store committed. Likewise, a panic at the writer is not
evidence of a later readback when the stack ends inside the write primitive.

## Symbolicate Cyanide frames

Use the exact `.app` produced by the build that was installed when the panic
occurred. A different build can produce plausible but incorrect symbols.

```sh
CND_APP='/absolute/path/to/the/matching/Cyanide.app'
xcrun dwarfdump --uuid "$CND_APP/Cyanide"
```

Match that UUID to an entry in the panic's `binaryImages` array. Each
`userFrames` pair is `[binary-image-index, offset-within-image]`; calculate the
runtime address as `binaryImages[index][1] + offset`. The following prints the
load address and calculated Cyanide addresses for every thread:

```sh
CND_APP_UUID='PUT-THE-MATCHING-UUID-HERE'

python3 - "$CND_CAPTURE_DIR/$CND_CRASH_REPORT" "$CND_APP_UUID" <<'PY'
import json
import sys

text = open(sys.argv[1]).read()
decoder = json.JSONDecoder()
_, offset = decoder.raw_decode(text)
while offset < len(text) and text[offset].isspace():
    offset += 1
payload, _ = decoder.raw_decode(text, offset)

wanted = sys.argv[2].lower()
images = payload.get("binaryImages", [])
matches = [
    index for index, image in enumerate(images)
    if image and str(image[0]).lower() == wanted
]
if len(matches) != 1:
    raise SystemExit(f"expected one matching image, found {matches}")

image_index = matches[0]
load_address = int(images[image_index][1])
print(f"image-index={image_index} load-address={load_address:#x}")

for pid, process in payload.get("processByPid", {}).items():
    for tid, thread in process.get("threadById", {}).items():
        addresses = [
            load_address + int(frame[1])
            for frame in thread.get("userFrames", [])
            if int(frame[0]) == image_index
        ]
        if addresses:
            rendered = " ".join(f"{address:#x}" for address in addresses)
            print(f"pid={pid} process={process.get('procname')} tid={tid}")
            print(rendered)
PY
```

Pass the printed load address and runtime addresses to `atos`:

```sh
atos -arch arm64e \
  -o "$CND_APP/Cyanide" \
  -l 0xLOAD_ADDRESS \
  0xFRAME_ADDRESS_1 0xFRAME_ADDRESS_2
```

For kernel instructions, first verify that the local kernelcache's UUID and OS
build exactly match the panic. Normalize a kernel PC by subtracting the
reported kernel text-exec base; do not symbolicate it against a different
build or device kernelcache.

## Unified logs

Collect the device's recent unified log into a `.logarchive`:

```sh
/usr/bin/log collect \
  --device-name "$CND_DEVICE_NAME" \
  --last 1h \
  --output "$CND_CAPTURE_DIR/device.logarchive"
```

Extract Cyanide messages from the archive:

```sh
/usr/bin/log show "$CND_CAPTURE_DIR/device.logarchive" \
  --style compact \
  --info \
  --debug \
  --predicate 'process == "Cyanide"' \
  > "$CND_CAPTURE_DIR/Cyanide-unified.log"
```

For live syslog, this Mac also has `libimobiledevice`. Its UDID is not the
CoreDevice ID, so obtain it separately:

```sh
idevice_id -l
CND_DEVICE_UDID='PUT-THE-USB-UDID-HERE'
idevicesyslog \
  --udid "$CND_DEVICE_UDID" \
  --process Cyanide \
  --no-colors \
  --output "$CND_CAPTURE_DIR/Cyanide-live-syslog.log"
```

Stop the live relay with Control-C after reproducing the issue.

## Full sysdiagnose

Use a sysdiagnose when targeted app/crash logs are insufficient. It is much
larger and slower than the collections above.

```sh
xcrun devicectl device sysdiagnose \
  --device "$CND_DEVICE_ID" \
  --destination "$CND_CAPTURE_DIR/sysdiagnose" \
  --gather-full-logs \
  --timeout 1800 \
  --json-output "$CND_CAPTURE_DIR/sysdiagnose-result.json"
```

## Correlation checklist

1. Preserve the evidence in a fresh capture directory; do not overwrite an
   older run.
2. Compare times carefully: `chain-*.log` and panic headers use device-local
   time, while CoreDevice file metadata commonly uses UTC with a trailing `Z`.
3. Identify the exact installed bundle/build and whether Cyanide, SpringBoard,
   and Spotlight restarted or changed PID.
4. Read the latest Cyanide session log and feature report together.
5. Match the nearest `.ips` report by event time and panicked/crashed process.
6. Verify binary and kernelcache UUIDs before symbolication.
7. Distinguish a durable pre-operation checkpoint from a completion record.
   Absence of the latter after a panic means the outcome is unknown, not that
   the operation necessarily did nothing.
