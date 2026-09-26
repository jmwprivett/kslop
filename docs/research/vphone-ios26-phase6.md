# Phase 6 vphone icon-source lab

This is a macOS-host-only research harness for one controlled experiment on
the jailbroken iOS 26.0 vphone. It is not a Cyanide feature and it does not
install, attach to, restart, unregister, rebuild, or clear anything on the
device. In particular, LaunchServices, IconServices, Spotlight, alternate
icons, cache stores, SpringBoard, exploit/session activation, and
`CyanideLabBridge` remain operator-owned/manual gates.

The expected identity is pinned in the script and every prepared journal:

| field | required value |
| --- | --- |
| UDID | `<VM_UDID>` |
| iOS | `26.0` |
| build | `23A341` |
| SSH port | `22222` |
| bundle ID | `com.zeroxjf.ios-cyanide1` |

The evidence default is
`${HOME}/Library/CyanideVPhoneLab/evidence/phase6/<run-id>/`. The
diagnostic artifact is exactly `build/Cyanide-1.6-spotlight.ipa`; the harness
refuses `build/Cyanide.ipa`. The theme archive is exactly
`purple accent pulsar.theme.zip`, and its required entry is
`purple accent pulsar.theme/IconBundles/com.zeroxjf.ios-cyanide1-large.png`.

## Safety model

`preflight` is read-only. It requires explicit VM bundle and config paths,
checks all five identity fields, validates the diagnostic IPA and exact theme
entry, and optionally validates a checkpoint and app-backup evidence tree. It
does not infer identity from an IP address, stale app-container UUID, or a
guessed `AppIcon60x60` name.

The prepared manifest must explicitly provide:

* `resolved_arm.kind`: `car`, `png`, or `declaration-redirect` (the aliases
  `redirect` and `declaration` are normalized to the last value);
* an absolute `resolved_arm.path`;
* a non-empty `allowlisted_mapping` list, where every target and staged
  replacement is an absolute exact path and has original/replacement SHA-256
  values plus complete original metadata (a newly introduced file additionally
  needs explicit `replacement_metadata`);
* a non-empty generated `recovery_command`; and
* `manual_invalidation_acknowledged: true`.

No arm is selected automatically. Every target is re-resolved and its bytes
and metadata are checked immediately before the first write. Any mismatch is
a refusal.

The real guest exposes GNU `stat` with nanosecond timestamps and Apple's
`xattr`, but GNU `stat` does not print Darwin file flags. A bounded probe in
`/var/tmp` verified that this VM's `/var/jb/bin/cp --preserve=all` carries both
a non-zero `hidden` flag (`0100000`) and a binary xattr to its sibling. The SSH
write path therefore inventories xattrs directly and preserves file flags
opaquely: it seeds the sibling from the live target, writes only the bytes,
then reapplies all attributes from the live target before the atomic rename.
The probe files were cleared and removed; no application file was involved.

A checkpoint is accepted only when an explicitly supplied sidecar says that
it is a verified, cold full-VM, identity-preserving checkpoint, the guest was
stopped, and `Disk.img` had no open handles. The harness never force-stops a
VM, invokes `vphone vm clone`, or creates a checkpoint from an unproven live
disk. A sidecar can be `checkpoint.json`, `metadata.json`, or `identity.json`
inside the selected checkpoint directory (or the corresponding
`<checkpoint>.checkpoint.json`/`.metadata.json`/`.json` file). Required keys
are `verified`, `cold`, `vm_stopped` (or `guest_stopped`), `disk_open: false`,
`identity_preserved: true`, and the complete `identity` object.

An app backup is an explicit directory containing `contents/` and a verified
`inventory.json`. The inventory includes SHA-256, owner/group, modes, xattrs,
flags, symlink targets, and nanosecond timestamps. `create_app_backup()` is a
narrow, non-overwriting tree copy; it never follows symlinks or recursively
deletes a destination.

## Journal and operations

The durable `journal.json` records the manifest, evidence, operations, and
state transitions:

`new -> prepared -> applying -> applied -> restoring -> restored ->
verified-restored`

An incomplete apply or restore records `rollback-required`. The journal is
written atomically with a fsynced sibling temporary file. Apply records
`applying` before the first guest write, journals every temporary sibling
before readback, verifies the replacement hash, and atomically renames the
sibling over the exact target. Restore removes only journaled, not-original
files and restores original bytes from that run's `originals/` directory;
repeating restore is safe and idempotent. A changed target is never
overwritten during restore.

The final verification checks original bytes and all recorded metadata. It
also requires a real operator-evidence file documenting equivalent
LaunchServices, IconServices, and Spotlight invalidation. The harness records
that need but does not perform those operations.

## Usage

Help is available without touching the VM:

```sh
python3 scripts/vphone_icon_source_lab.py --help
python3 scripts/vphone_icon_source_lab.py --run-id phase6-2026-09-08 \
  --vm-bundle /path/to/vphone.bundle --vm-config /path/to/vm.json \
  --identity-file /path/to/identity.json preflight
```

Preparation additionally requires `--manifest`, `--checkpoint`, and
`--app-backup`. It writes only the new evidence run and host-side original
captures. Apply and restore require both `--execute` and the literal
confirmation `--confirm PHASE6-EXECUTE`; without an explicit `--host`, the
only supported alternative is a test/local fixture transport supplied with
both `--local-root` and `--local-identity`. SSH actions also require the
explicit pinned identity (`--identity-file` or config). Password login is
opt-in through `--ssh-password-env NAME`; the secret is passed to `sshpass`
through its environment and never placed in the command line or journal. SSH
uses a dedicated `--known-hosts` file with `accept-new`, so a changed key is
rejected after first contact. `--dry-run` performs no guest write.

The script does not call `scripts/build.sh`, does not repoint either IPA, and
does not issue arbitrary remote commands. The SSH adapter uses only fixed
`cat`, `realpath`/`readlink`, `stat`, `sha256sum`, `xattr`, `cp`, `tee`, `mv`,
and `rm` operations from the observed `/var/jb` or `/iosbinpack64` toolchains,
with validated absolute paths. The provided tests use local temporary fixtures
and never contact the VM.
