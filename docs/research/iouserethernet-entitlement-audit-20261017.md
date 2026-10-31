# IOUserEthernet entitlement audit — device evidence (23A341 / iPhone17,2)

Read-only companion to `label-borrow-physical-refusal-23A341-iphone17,2.md`.
The borrow cannot land on the phone, so the donor question — *does `bluetoothd`
actually carry `com.apple.networking.ethernet.user-access`?* — has to be
answered without writing anything. This note records what the in-app probe
(`Cyanide/CNDPhysicalEntitlementAuditProbe.{h,m}`) proved on the device so far.

## Offline facts the probe is built on

* The gate itself is real and is checked against the opening task:
  `IOUserEthernetResourceUserClient::initWithTask` →
  `IOTaskHasEntitlement(task, "com.apple.networking.ethernet.user-access")`
  (`build/rea-secure-execution-23A341-iphone17,2/kernel-filesets-stock/com.apple.iokit.IOUserEthernet`).
* The donor choice is corroborated by the sandbox kext: `com.apple.security.sandbox`
  carries a profile table naming `/usr/sbin/bluetoothd` together with
  `IOUserEthernetResourceUserClient` / `IOUserEthernetResource`
  (file offset `0x192179`).
* The entitlement string itself is **not** in the kernelcache — it is
  code-signature data attached to the running process, so only a device read can
  settle it.

## Method

For each candidate process: `proc_find_by_name` → `proc_get_cred_label` → the
AMFI policy object at `label + 0x8` → a depth-first walk of that object's
reachable pointers looking for the entitlement string. Reads only, on the app's
own kexploit KRW; no writes, no borrow, no kernel call, no provider, no root.

Every read is bounded, every followed pointer is validated against the phone's
kernel object window (`0xffffffdc00000000`–`0xfffffffbffffffff`), both PAC strips
are tried before a raw pointer is used, and the report carries `scanNodes`,
`scanReads`, `scanTruncated` and up to eight sample `com.apple.*` strings so a
`false` verdict can be judged instead of trusted. A truncated walk is never
presented as "no entitlement".

## What the device runs established

Three runs, each a signed install of `com.zeroxjf.ios-cyanide1` 1.6 (1005002),
launched with `--entitlement-audit-probe`:

1. **Resolution and KRW all work.** `krwInitiallyReady`/`krwValidated` true,
   `kernelBase 0xfffffff03d1f8000`, `kernelSlide 0x361f4000`,
   `kernelBaseMatchesContainer` true, header `0xfeedfacf` / `MH_FILESET`,
   `amfiSlotOffset 8`, `sandboxSlotOffset 16`. All five candidates resolved to
   distinct `proc` / `label` / `amfiObject` / `sandboxObject` values, e.g.
   bluetoothd `proc 0xffffffdf02671660`, `label 0xffffffdce800c800`,
   `amfi 0xffffffde1b669350`.
2. **The walk reaches real entitlement data.** With the first (breadth-first)
   scan it truncated at 21 nodes per process with zero strings — the worklist
   floods on metadata. After switching to a depth-first walk and never following
   a node's isa/class word, the sampled strings are genuine per-process
   entitlements:
   * bluetoothd: `com.apple.bluetoothd0`, `com.apple.BTServer.avrcp`,
     `com.apple.BTServer.le`, `com.apple.BluetoothServices`
   * configd: `com.apple.configd`, `com.apple.bluetooth.discovery`,
     `com.apple.server.bluetooth`
   * nehelper: an entire XML entitlements blob (`…</key>`, `…</string>`),
     e.g. `com.apple.networkextension.keychain`, which also shows the walk can
     read a contiguous blob when it reaches one
   * symptomsd / wifid: their own `com.apple.*` sets
3. **Still open:** the last two runs truncated before finishing each process's
   graph (`scanTruncated: true`), so `donorHasEntitlement: false` so far is
   *not* yet a conclusion — it is a walk that stopped early. The installed build
   under test at that point used 0x40-byte deep windows; the current source uses
   0x80 (a 37-character key starting at offset 0x38 must not be split across a
   window edge) with a 40000-read budget per process.

## Verdict to date

* `com.apple.networking.ethernet.user-access` has **not** been observed in
  bluetoothd's AMFI object on the device.
* That is not yet decisive, because no run has completed an untruncated walk of
  the donor's entitlement graph.

## Next step

Install the current build, run `--entitlement-audit-probe` (or tap
"Audit IOUserEthernet Entitlement" in Settings → Probes), and read
`CNDPhysicalEntitlementAuditProbe.json`. The result is decisive once every
candidate reports `scanTruncated: false`:

* `donorHasEntitlement: true` → the label-borrow premise was right and only the
  write transport is missing.
* `donorHasEntitlement: false` with `scanTruncated: false` → bluetoothd is not a
  usable donor on this build; pick from `processesWithEntitlement`, or treat the
  sandbox profile table as an allow-list rather than an entitlement grant.
